// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 Heiner Litz
 * Initial release: Heiner Litz <hlitz@ucsc.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * pblk-rail.c - pblk's RAIL path
 */

#include "pblk.h"

/* Distinguishes parity from data writes, used by map_page_data */
#define PBLK_RAIL_PARITY_FLAG (1 << 15)

int pblk_rail_stride_width(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_rail *rail = &pblk->rail;

	return rail->stride_width ? rail->stride_width : geo->rail_stride_width;
}

/* RAIL auxiliary functions */
static unsigned int pblk_rail_nr_parity_luns(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;

	return lm->blk_per_line / pblk_rail_stride_width(pblk);
}

static unsigned int pblk_rail_sec_per_stripe(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;

	return lm->blk_per_line * pblk->min_write_pgs;
}

static unsigned int pblk_rail_psec_per_stripe(struct pblk *pblk)
{
	return pblk_rail_nr_parity_luns(pblk) * pblk->min_write_pgs;
}

static unsigned int pblk_rail_dsec_per_stripe(struct pblk *pblk)
{
	return pblk_rail_sec_per_stripe(pblk) - pblk_rail_psec_per_stripe(pblk);
}

static unsigned int pblk_rail_wrap_lun(struct pblk *pblk, unsigned int lun)
{
	struct pblk_line_meta *lm = &pblk->lm;

	return (lun & (lm->blk_per_line - 1));
}

static unsigned int pblk_rail_nr_data_luns(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;

	return lm->blk_per_line - pblk_rail_nr_parity_luns(pblk);
}

bool pblk_rail_meta_distance(struct pblk *pblk, struct pblk_line *data_line)
{
	return (data_line->meta_distance % pblk_rail_stride_width(pblk)) == 0;
}

/* Notify readers that LUN is serving high latency operation */
static void pblk_rail_notify_reader_down(struct pblk *pblk, int lun)
{
	WARN_ON(test_and_set_bit(lun, pblk->rail.busy_bitmap));
	/* Make sure that busy bit is seen by reader before proceeding */
	smp_mb__after_atomic();
}

static void pblk_rail_notify_reader_up(struct pblk *pblk, int lun)
{
	/* Make sure that write is completed before releasing busy bit */
	smp_mb__before_atomic();
	WARN_ON(!test_and_clear_bit(lun, pblk->rail.busy_bitmap));
}

static int pblk_rail_lun_busy(struct pblk *pblk, struct ppa_addr ppa)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int lun_pos = pblk_ppa_to_pos(geo, ppa);

	return test_bit(lun_pos, pblk->rail.busy_bitmap);
}

/* Enforces one writer per stride */
int pblk_rail_down_stride(struct pblk *pblk, int lun_pos, int timeout)
{
	struct pblk_lun *rlun;
	int strides = pblk_rail_nr_parity_luns(pblk);
	int stride = lun_pos % strides;
	int ret;

	rlun = &pblk->luns[stride];
	ret = down_timeout(&rlun->wr_sem, timeout);
	pblk_rail_notify_reader_down(pblk, lun_pos);

	return ret;
}

void pblk_rail_up_stride(struct pblk *pblk, int lun_pos)
{
	struct pblk_lun *rlun;
	int strides = pblk_rail_nr_parity_luns(pblk);
	int stride = lun_pos % strides;

	pblk_rail_notify_reader_up(pblk, lun_pos);
	rlun = &pblk->luns[stride];
	up(&rlun->wr_sem);
}

/* Determine whether a sector holds data, meta or is bad*/
static bool pblk_rail_valid_sector(struct pblk *pblk, struct pblk_line *line,
				   int pos)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr ppa;
	int lun;

	if (pos >= line->smeta_ssec && pos < (line->smeta_ssec + lm->smeta_sec))
		return false;

	if (pos >= line->emeta_ssec &&
	    pos < (line->emeta_ssec + lm->emeta_sec[0]))
		return false;

	ppa = addr_to_gen_ppa(pblk, pos, line->id);
	lun = pblk_ppa_to_pos(geo, ppa);

	return !test_bit(lun, line->blk_bitmap);
}

static unsigned int pblk_rail_sec_to_stride(struct pblk *pblk, unsigned int sec)
{
	unsigned int sec_in_stripe = sec % pblk_rail_sec_per_stripe(pblk);
	int page = sec_in_stripe / pblk->min_write_pgs;

	return page % pblk_rail_nr_parity_luns(pblk);
}

static unsigned int pblk_rail_sec_to_idx(struct pblk *pblk, unsigned int sec)
{
	unsigned int sec_in_stripe = sec % pblk_rail_sec_per_stripe(pblk);

	return sec_in_stripe / pblk_rail_psec_per_stripe(pblk);
}

static void pblk_rail_data_parity(void *dest, void *src)
{
	unsigned int i;

	for (i = 0; i < PBLK_EXPOSED_PAGE_SIZE / sizeof(unsigned long); i++)
		((unsigned long *)dest)[i] ^= ((unsigned long *)src)[i];
}

static void pblk_rail_lba_parity(u64 *dest, u64 *src)
{
	*dest ^= *src;
}

/* Tracks where a sector is located in the rwb */
static void pblk_rail_track_sec(struct pblk *pblk, struct pblk_line *line,
				int cur_sec, int sentry, int nr_valid)
{
	int stride, idx, pos;

	stride = pblk_rail_sec_to_stride(pblk, cur_sec);
	idx = pblk_rail_sec_to_idx(pblk, cur_sec);
	pos = pblk_rb_wrap_pos(&pblk->rwb, sentry);
	pblk->rail.p2b[stride][idx].pos = pos;
	pblk->rail.p2b[stride][idx].nr_valid = nr_valid;
}

/* RAIL's recovery path */
bool pblk_rail_lun_is_parity(struct pblk *pblk, struct pblk_line *line, int lun)
{
	struct pblk_line_meta *lm = &pblk->lm;
	int stride_width = line->rail_stride_width;
	int data_luns;

	if (!stride_width)
		return false;

	WARN(stride_width != pblk->rail.stride_width,
	     "Inconsistent RAIL stride width, line: %i geo: %i",
	     stride_width, pblk->rail.stride_width);

	pblk->rail.stride_width = stride_width;
	data_luns = lm->blk_per_line - lm->blk_per_line / stride_width;
	return (lun >= data_luns);
}

/* RAIL's sector mapping function */
void pblk_rail_map_sec(struct pblk *pblk, struct pblk_line *line, int sentry,
		       struct pblk_sec_meta *meta_list, __le64 *lba_list,
		       struct ppa_addr ppa, u64 paddr, int sec, int valid)
{
	if (sentry & PBLK_RAIL_PARITY_FLAG) {
		u64 *lba;

		kref_get(&line->ref);
		sentry &= ~PBLK_RAIL_PARITY_FLAG;
		lba = &pblk->rail.lba[sentry];
		meta_list->lba = cpu_to_le64(*lba);
		*lba_list = cpu_to_le64(*lba);

		spin_lock(&line->lock);
		if (test_and_set_bit(paddr, line->invalid_bitmap)) {
			WARN_ONCE(1, "pblk: double invalidate\n");
			spin_unlock(&line->lock);
			return;
		}
		le32_add_cpu(line->vsc, -1);
		spin_unlock(&line->lock);
	} else {
		pblk_map_sec(pblk, line, sentry, meta_list, lba_list, ppa,
			     paddr, sec, valid);

		/* RAIL tracks pages not sectors */
		if (sec == 0)
			pblk_rail_track_sec(pblk, line, paddr, sentry, valid);
	}
}

/* RAIL Initialization and tear down */
int pblk_rail_init(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int i, p2be;
	unsigned int nr_strides;
	unsigned int psecs;
	void *kaddr;

	/* Check if stride width has been set by recovery already */
	if (!pblk->rail.stride_width)
		pblk->rail.stride_width = geo->rail_stride_width;

	if (!pblk->rail.stride_width)
		return 0;

	if (((lm->blk_per_line % pblk->rail.stride_width) != 0) ||
	    (lm->blk_per_line < pblk->rail.stride_width)) {
		pr_err("pblk: unsupported RAIL stride %i\n", lm->blk_per_line);
		return -EINVAL;
	}

	psecs = pblk_rail_psec_per_stripe(pblk);
	nr_strides = pblk_rail_sec_per_stripe(pblk) / pblk->rail.stride_width;

	pblk->rail.p2b = kmalloc_array(nr_strides, sizeof(struct p2b_entry *),
				       GFP_KERNEL);
	if (!pblk->rail.p2b)
		return -ENOMEM;

	for (p2be = 0; p2be < nr_strides; p2be++) {
		pblk->rail.p2b[p2be] = kmalloc_array(pblk->rail.stride_width,
						     sizeof(struct p2b_entry),
						     GFP_KERNEL);
		if (!pblk->rail.p2b[p2be])
			goto free_p2b_entries;
	}

	pblk->rail.data = kmalloc(psecs * sizeof(void *), GFP_KERNEL);
	if (!pblk->rail.data)
		goto free_p2b_entries;

	pblk->rail.pages = alloc_pages(GFP_KERNEL, get_count_order(psecs));
	if (!pblk->rail.pages)
		goto free_data;

	kaddr = page_address(pblk->rail.pages);
	for (i = 0; i < psecs; i++)
		pblk->rail.data[i] = kaddr + i * PBLK_EXPOSED_PAGE_SIZE;

	pblk->rail.lba = kmalloc_array(psecs, sizeof(u64 *), GFP_KERNEL);
	if (!pblk->rail.lba)
		goto free_pages;

	/* Subtract parity bits from device capacity */
	pblk->capacity = pblk->capacity * (pblk->rail.stride_width - 1) /
		pblk->rail.stride_width;

	/* RAIL reads require the entire active stripe be resident in the rb */
	WARN_ON(pblk->rwb.back_thres < (pblk->min_write_pgs * geo->all_luns));

	return 0;

free_pages:
	free_pages((unsigned long)page_address(pblk->rail.pages),
		   get_count_order(psecs));
free_data:
	kfree(pblk->rail.data);
free_p2b_entries:
	for (p2be = p2be - 1; p2be >= 0; p2be--)
		kfree(pblk->rail.p2b[p2be]);
	kfree(pblk->rail.p2b);

	return -ENOMEM;
}

void pblk_rail_free(struct pblk *pblk)
{
	unsigned int i;
	unsigned int nr_strides;
	unsigned int psecs;

	if (!pblk->rail.stride_width)
		return;

	psecs = pblk_rail_psec_per_stripe(pblk);
	nr_strides = pblk_rail_sec_per_stripe(pblk) / pblk->rail.stride_width;

	kfree(pblk->rail.lba);
	free_pages((unsigned long)page_address(pblk->rail.pages),
		   get_count_order(psecs));
	kfree(pblk->rail.data);
	for (i = 0; i < nr_strides; i++)
		kfree(pblk->rail.p2b[i]);
	kfree(pblk->rail.p2b);
}

/* PBLK supports 64 ppas max. By performing RAIL reads, a sector is read using
 * multiple ppas which can lead to violation of the 64 ppa limit. In this case,
 * split the bio
 */
static void pblk_rail_bio_split(struct pblk *pblk, struct bio **bio, int sec)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct bio *split;

	sec *= (dev->geo.csecs >> 9);

	split = bio_split(*bio, sec, GFP_KERNEL, &pblk_bio_set);
	/* there isn't chance to merge the split bio */
	split->bi_opf |= REQ_NOMERGE;
	bio_set_flag(*bio, BIO_QUEUE_ENTERED);
	bio_chain(split, *bio);
	generic_make_request(*bio);
	*bio = split;
}

/* RAIL's Write Path */
static int pblk_rail_sched_parity(struct pblk *pblk)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	unsigned int sec_in_stripe;

	while (1) {
		sec_in_stripe = line->cur_sec % pblk_rail_sec_per_stripe(pblk);

		/* Schedule parity write at end of data section */
		if (sec_in_stripe >= pblk_rail_dsec_per_stripe(pblk))
			return 1;

		/* Skip bad blocks and meta sectors until we find a valid sec */
		if (test_bit(line->cur_sec, line->map_bitmap))
			line->cur_sec += pblk->min_write_pgs;
		else
			break;
	}

	return 0;
}

static void pblk_rail_end_io_write(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	if (rqd->error)
		pblk_log_write_err(pblk, rqd);
#ifdef CONFIG_NVM_DEBUG
	else
		WARN_ONCE(rqd->bio->bi_status, "pblk: corrupted write error\n");
#endif
	pblk_up_rq(pblk, c_ctx->lun_bitmap);

	pblk_rq_to_line_put(pblk, rqd);
	bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, PBLK_WRITE);

	atomic_dec(&pblk->inflight_io);
}

static int pblk_rail_read_to_bio(struct pblk *pblk, struct nvm_rq *rqd,
			  struct bio *bio, unsigned int stride,
			  unsigned int nr_secs, unsigned int paddr)
{
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	int sec, i;
	int nr_data = pblk_rail_stride_width(pblk) - 1;
	struct pblk_line *line = pblk_line_get_data(pblk);

	c_ctx->nr_valid = nr_secs;
	/* sentry indexes rail page buffer, instead of rwb */
	c_ctx->sentry = stride * pblk->min_write_pgs;
	c_ctx->sentry |= PBLK_RAIL_PARITY_FLAG;

	for (sec = 0; sec < pblk->min_write_pgs; sec++) {
		void *pg_addr;
		struct page *page;
		u64 *lba;

		lba = &pblk->rail.lba[stride * pblk->min_write_pgs + sec];
		pg_addr = pblk->rail.data[stride * pblk->min_write_pgs + sec];
		page = virt_to_page(pg_addr);

		if (!page) {
			pr_err("pblk: could not allocate RAIL bio page %p\n",
			       pg_addr);
			return -NVM_IO_ERR;
		}

		if (bio_add_page(bio, page, pblk->rwb.seg_size, 0) !=
		    pblk->rwb.seg_size) {
			pr_err("pblk: could not add page to RAIL bio\n");
			return -NVM_IO_ERR;
		}

		*lba = 0;
		memset(pg_addr, 0, PBLK_EXPOSED_PAGE_SIZE);

		for (i = 0; i < nr_data; i++) {
			struct pblk_rb_entry *entry;
			struct pblk_w_ctx *w_ctx;
			u64 lba_src;
			unsigned int pos;
			unsigned int cur;
			int distance = pblk_rail_psec_per_stripe(pblk);

			cur = paddr - distance * (nr_data - i) + sec;

			if (!pblk_rail_valid_sector(pblk, line, cur))
				continue;

			pos = pblk->rail.p2b[stride][i].pos;
			pos = pblk_rb_wrap_pos(&pblk->rwb, pos + sec);
			entry = &pblk->rwb.entries[pos];
			w_ctx = &entry->w_ctx;
			lba_src = w_ctx->lba;

			if (sec < pblk->rail.p2b[stride][i].nr_valid &&
			    lba_src != ADDR_EMPTY) {
				pblk_rail_data_parity(pg_addr, entry->data);
				pblk_rail_lba_parity(lba, &lba_src);
			}
		}
	}

	return 0;
}

int pblk_rail_submit_write(struct pblk *pblk)
{
	int i;
	struct nvm_rq *rqd;
	struct bio *bio;
	struct pblk_line *line = pblk_line_get_data(pblk);
	int start, end, bb_offset;
	unsigned int stride = 0;

	if (!pblk_rail_sched_parity(pblk))
		return 0;

	start = line->cur_sec;
	bb_offset = start % pblk_rail_sec_per_stripe(pblk);
	end = start + pblk_rail_sec_per_stripe(pblk) - bb_offset;

	for (i = start; i < end; i += pblk->min_write_pgs, stride++) {
		/* Do not generate parity in this slot if the sec is bad
		 * or reserved for meta.
		 * We check on the read path and perform a conventional
		 * read, to avoid reading parity from the bad block
		 */
		if (!pblk_rail_valid_sector(pblk, line, i))
			continue;

		rqd = pblk_alloc_rqd(pblk, PBLK_WRITE);
		if (IS_ERR(rqd)) {
			pr_err("pblk: cannot allocate parity write req.\n");
			return -ENOMEM;
		}

		bio = bio_alloc(GFP_KERNEL, pblk->min_write_pgs);
		if (!bio) {
			pr_err("pblk: cannot allocate parity write bio\n");
			pblk_free_rqd(pblk, rqd, PBLK_WRITE);
			return -ENOMEM;
		}

		bio->bi_iter.bi_sector = 0; /* internal bio */
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
		rqd->bio = bio;

		pblk_rail_read_to_bio(pblk, rqd, bio, stride,
				      pblk->min_write_pgs, i);

		if (pblk_submit_io_set(pblk, rqd, pblk_rail_end_io_write)) {
			bio_put(rqd->bio);
			pblk_free_rqd(pblk, rqd, PBLK_WRITE);
			pr_err("pblk: RAIL write submission failed\n");

			return -NVM_IO_ERR;
		}
	}

	return 0;
}

/* RAIL's Read Path */
static void pblk_rail_end_io_read(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_pr_ctx *pr_ctx = r_ctx->private;
	struct bio *new_bio = rqd->bio;
	struct bio *bio = pr_ctx->orig_bio;
	struct bio_vec src_bv, dst_bv;
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	int bio_init_idx = pr_ctx->bio_init_idx;
	int nr_secs = pr_ctx->orig_nr_secs;
	__le64 *lba_list_mem, *lba_list_media;
	__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);
	void *src_p, *dst_p;
	int i, r, rail_ppa = 0;
	unsigned char valid;

	if (unlikely(rqd->nr_ppas == 1)) {
		struct ppa_addr ppa;

		ppa = rqd->ppa_addr;
		rqd->ppa_list = pr_ctx->ppa_ptr;
		rqd->dma_ppa_list = pr_ctx->dma_ppa_list;
		rqd->ppa_list[0] = ppa;
	}

	if (rqd->error) {
		pblk_log_read_err(pblk, rqd);
		rqd->error = 0;
	}

	/* Re-use allocated memory for intermediate lbas */
	lba_list_mem = (((void *)rqd->ppa_list) + pblk_dma_ppa_size);
	lba_list_media = (((void *)rqd->ppa_list) + 2 * pblk_dma_ppa_size);

	for (i = 0; i < rqd->nr_ppas; i++)
		lba_list_media[i] = meta_list[i].lba;
	for (i = 0; i < nr_secs; i++)
		meta_list[i].lba = lba_list_mem[i];

	for (i = 0; i < nr_secs; i++) {
		struct pblk_line *line;
		u64 meta_lba = 0x0UL, mlba;

		line = pblk_ppa_to_line(pblk, rqd->ppa_list[rail_ppa]);

		valid = bitmap_weight(pr_ctx->bitmap, pblk_rail_stride_width(pblk));
		bitmap_shift_right(pr_ctx->bitmap, pr_ctx->bitmap,
				   pblk_rail_stride_width(pblk),
				   NVM_MAX_VLBA * pblk_rail_stride_width(pblk));

		if (valid == 0) /* Skip cached reads */
			continue;

		kref_put(&line->ref, pblk_line_put);

		dst_bv = bio->bi_io_vec[bio_init_idx + i];
		dst_p = kmap_atomic(dst_bv.bv_page);

		memset(dst_p + dst_bv.bv_offset, 0, PBLK_EXPOSED_PAGE_SIZE);
		meta_list[i].lba = cpu_to_le64(0x0UL);

		for (r = 0; r < valid; r++, rail_ppa++) {
			src_bv = new_bio->bi_io_vec[rail_ppa];

			if (lba_list_media[rail_ppa] != addr_empty) {
				src_p = kmap_atomic(src_bv.bv_page);
				pblk_rail_data_parity(dst_p + dst_bv.bv_offset,
						      src_p + src_bv.bv_offset);
				mlba = le64_to_cpu(lba_list_media[rail_ppa]);
				pblk_rail_lba_parity(&meta_lba, &mlba);
				kunmap_atomic(src_p);
			}

			mempool_free(src_bv.bv_page, &pblk->page_bio_pool);
		}
		meta_list[i].lba = cpu_to_le64(meta_lba);
		kunmap_atomic(dst_p);
	}

	bio_put(new_bio);
	rqd->nr_ppas = pr_ctx->orig_nr_secs;
	kfree(pr_ctx->bitmap);
	kfree(pr_ctx);
	rqd->bio = NULL;

	bio_endio(bio);
	__pblk_end_io_read(pblk, rqd, false);
}

/* Converts original ppa into ppa list of RAIL reads */
static int pblk_rail_setup_ppas(struct pblk *pblk, struct ppa_addr ppa,
				struct ppa_addr *rail_ppas,
				unsigned char *pvalid, int *nr_rail_ppas,
				int *rail_reads)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct ppa_addr rail_ppa = ppa;
	unsigned int lun_pos = pblk_ppa_to_pos(geo, ppa);
	unsigned int strides = pblk_rail_nr_parity_luns(pblk);
	struct pblk_line *line = pblk_ppa_to_line(pblk, ppa);
	unsigned int i;
	int ppas = *nr_rail_ppas;
	int valid = 0;

	/* Write errors can corrupt parity. Rare, so just fall back */
	if (line->w_err_gc->has_write_err)
		return 0;

	for (i = 1; i < pblk_rail_stride_width(pblk); i++) {
		unsigned int neighbor, lun, chnl;
		int laddr;

		neighbor = pblk_rail_wrap_lun(pblk, lun_pos + i * strides);

		lun = pblk_pos_to_lun(geo, neighbor);
		chnl = pblk_pos_to_chnl(geo, neighbor);
		rail_ppa.a.lun = lun;
		rail_ppa.a.ch = chnl;

		laddr = pblk_dev_ppa_to_line_addr(pblk, rail_ppa);

		/* Do not read from bad blocks */
		if (!pblk_rail_valid_sector(pblk, line, laddr)) {
			/* Perform regular read if parity sector is bad */
			if (neighbor >= pblk_rail_nr_data_luns(pblk))
				return 0;

			/* If any other neighbor is bad we can just skip it */
			continue;
		}

		rail_ppas[ppas++] = rail_ppa;
		valid++;
	}

	if (valid == 1)
		return 0;

	*pvalid = valid;
	*nr_rail_ppas = ppas;
	(*rail_reads)++;
	return 1;
}

static void pblk_rail_set_bitmap(struct pblk *pblk, struct ppa_addr *ppa_list,
				 int valid_idx, struct ppa_addr *rail_ppa_list,
				 int *nr_rail_ppas, unsigned long *read_bitmap,
				 unsigned long *pvalid, int *rail_reads)
{
	unsigned char valid;

	if (pblk_rail_lun_busy(pblk, *ppa_list) &&
	    pblk_rail_setup_ppas(pblk, *ppa_list,
				 rail_ppa_list, &valid,
				 nr_rail_ppas, rail_reads)) {
		bitmap_set(pvalid, valid_idx * pblk_rail_stride_width(pblk), valid);
	} else {
		rail_ppa_list[(*nr_rail_ppas)++] = *ppa_list;
		bitmap_set(pvalid, valid_idx * pblk_rail_stride_width(pblk), 1);
	}
}

int pblk_rail_read_bio(struct pblk *pblk, struct nvm_rq *rqd, int blba,
		       unsigned long *read_bitmap, int bio_init_idx,
		       struct bio **bio)
{
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_pr_ctx *pr_ctx;
	struct ppa_addr rail_ppa_list[NVM_MAX_VLBA];
	struct ppa_addr *ppa_list = nvm_rq_to_ppa_list(rqd);
	unsigned long *pvalid;
	int nr_secs = rqd->nr_ppas;
	int nr_rail_ppas = 0, rail_reads = 0;
	int i, ppa = 0;
	int ret;

	/* Fully cached reads should not enter this path */
	WARN_ON(bitmap_full(read_bitmap, nr_secs));

	pvalid = kcalloc(BITS_TO_LONGS(NVM_MAX_VLBA * pblk_rail_stride_width(pblk)),
			 sizeof(unsigned long), GFP_KERNEL);
	if (!pvalid)
		return NVM_IO_ERR;

	for (i = 0; i < rqd->nr_ppas; i++) {
		/* Don't use RAIL for cached reads */
		if (test_bit(i, read_bitmap))
			continue;

		pblk_rail_set_bitmap(pblk, &ppa_list[ppa++], i,
				     rail_ppa_list, &nr_rail_ppas,
				     read_bitmap, pvalid, &rail_reads);

		/* Don't split if this it the last ppa of the rqd */
		if (((nr_rail_ppas + pblk_rail_stride_width(pblk)) >=
		     NVM_MAX_VLBA) && (i + 1 < rqd->nr_ppas)) {
			struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);

			pblk_rail_bio_split(pblk, bio, i + 1);

			/* On split, avoid double ref counting on requeue */
			for (i += 1; i < rqd->nr_ppas; i++)
				pblk_ppa_to_line_put(pblk, ppa_list[ppa++]);

			rqd->nr_ppas = pblk_get_secs(*bio);
			r_ctx->private = *bio;
		}
	}

	if (!rail_reads) {
		kfree(pvalid);
		return NVM_IO_REQUEUE;
	}

	if (rqd->nr_ppas == 1 && nr_rail_ppas > 1) {
		rqd->ppa_list = rqd->meta_list + pblk_dma_meta_size;
		rqd->dma_ppa_list = rqd->dma_meta_list + pblk_dma_meta_size;
	}

	memcpy(rqd->ppa_list, rail_ppa_list, nr_rail_ppas *
	       sizeof(struct ppa_addr));

	if (pblk_setup_partial_read(pblk, rqd, bio_init_idx, read_bitmap,
				    nr_rail_ppas)) {
		kfree(pvalid);
		return NVM_IO_ERR;
	}

	rqd->end_io = pblk_rail_end_io_read;
	pr_ctx = r_ctx->private;

	/* Reuse readbitmap for valid bitmap */
	kfree(pr_ctx->bitmap);
	pr_ctx->bitmap = pvalid;

	ret = pblk_submit_io(pblk, rqd);
	if (ret) {
		bio_put(rqd->bio);
		pr_err("pblk: partial RAIL read IO submission failed\n");
		/* Free allocated pages in new bio */
		pblk_bio_free_pages(pblk, rqd->bio, 0, rqd->bio->bi_vcnt);
		kfree(pvalid);
		kfree(pr_ctx);
		__pblk_end_io_read(pblk, rqd, false);
		return NVM_IO_ERR;
	}

	return NVM_IO_OK;
}

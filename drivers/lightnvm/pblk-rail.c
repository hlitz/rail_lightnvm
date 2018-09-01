/*
 * Copyright (C) 2017 Heiner Litz <hlitz@ucsc.edu>
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
#include <linux/log2.h>

#define PBLK_RAIL_EMPTY ~0x0
#define PBLK_RAIL_PARITY_WRITE 0x8000

/* Generic auxiliary funtions */
static inline int pblk_pos_to_lun(struct nvm_geo *geo, int pos)
{
  return pos >> ilog2(geo->num_ch);
}

static inline int pblk_pos_to_chnl(struct nvm_geo *geo, int pos)
{
	return pos % geo->num_ch;
}

static inline void pblk_dev_ppa_set_lun(struct pblk *pblk, struct ppa_addr *p,
					int lun)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	if (geo->version == NVM_OCSSD_SPEC_12)
		p->g.lun = lun;
	else
		p->m.pu = lun;
}

static inline void pblk_dev_ppa_set_chnl(struct pblk *pblk, struct ppa_addr *p,
					 int chnl)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	if (geo->version == NVM_OCSSD_SPEC_12)
		p->g.ch = chnl;
	else
		p->m.grp = chnl;
}

/* RAIL specific auxiliary functions */
static unsigned int pblk_rail_nr_parity_luns(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;

	return lm->blk_per_line / PBLK_RAIL_STRIDE_WIDTH;
}

static unsigned int pblk_rail_nr_data_luns(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;

	return lm->blk_per_line - pblk_rail_nr_parity_luns(pblk);
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

bool pblk_rail_meta_distance(struct pblk_line *data_line)
{
	return (data_line->meta_distance % PBLK_RAIL_STRIDE_WIDTH) == 0;
}

void pblk_rail_adjust_capacity(struct pblk *pblk)
{
	pblk->capacity = pblk->capacity * (PBLK_RAIL_STRIDE_WIDTH - 1) /
		PBLK_RAIL_STRIDE_WIDTH;
}

/* Delay rb overwrite until whole stride has been written */
int pblk_rail_rb_delay(struct pblk_rb *rb)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);

	return pblk_rail_sec_per_stripe(pblk);
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

/* RAIL Initialization and tear down */
int pblk_rail_init(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;
	int i, p2be;
	unsigned int nr_strides;
	unsigned int psecs;
	void *kaddr;

	if (!PBLK_RAIL_STRIDE_WIDTH)
		return 0;

	if (((lm->blk_per_line % PBLK_RAIL_STRIDE_WIDTH) != 0) ||
	    (lm->blk_per_line < PBLK_RAIL_STRIDE_WIDTH)) {
		pr_err("pblk: unsupported RAIL stride %i\n", lm->blk_per_line);
		return -EINVAL;
	}
	
	psecs = pblk_rail_psec_per_stripe(pblk);
	nr_strides = pblk_rail_sec_per_stripe(pblk) / PBLK_RAIL_STRIDE_WIDTH;

	pblk->rail.p2b = kmalloc(nr_strides * sizeof(struct p2b_entry *),
				 GFP_KERNEL);
	if (!pblk->rail.p2b)
		return -ENOMEM;

	for (p2be = 0; p2be < nr_strides; p2be++) {
		pblk->rail.p2b[p2be] = kmalloc((PBLK_RAIL_STRIDE_WIDTH - 1) *
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

	pblk->rail.lba = kmalloc(psecs * sizeof(u64 *), GFP_KERNEL);
	if (!pblk->rail.lba)
		goto free_pages;

	pblk->rail.busy_bitmap = kzalloc(DIV_ROUND_UP(lm->blk_per_line,
						      BITS_PER_LONG) *
					 sizeof(unsigned long), GFP_KERNEL);
	if (!pblk->rail.busy_bitmap)
		goto free_lba;

	pblk->rail.stride_sem = kmalloc(nr_strides * sizeof(struct semaphore),
					GFP_KERNEL);
	if (!pblk->rail.stride_sem)
		goto free_busy;

	for (i = 0; i < nr_strides; i++)
		sema_init(&pblk->rail.stride_sem[i], 1);

	pblk->map_page = pblk_rail_map_page_data;
	printk(KERN_EMERG "Initialized RAIL with stride width %d\n",
	       PBLK_RAIL_STRIDE_WIDTH);

	return 0;

free_busy:
	kfree(pblk->rail.busy_bitmap);
free_lba:
	kfree(pblk->rail.lba);
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

	psecs = pblk_rail_psec_per_stripe(pblk);
	nr_strides = pblk_rail_sec_per_stripe(pblk) / PBLK_RAIL_STRIDE_WIDTH;

	kfree(pblk->rail.stride_sem);
	kfree(pblk->rail.busy_bitmap);
	kfree(pblk->rail.lba);
	free_pages((unsigned long)page_address(pblk->rail.pages),
		   get_count_order(psecs));
	kfree(pblk->rail.data);
	for (i = 0; i < nr_strides; i++)
		kfree(pblk->rail.p2b[i]);
	kfree(pblk->rail.p2b);
}

static void pblk_rail_bio_split(struct pblk *pblk, struct bio **bio, int sec)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct bio *split;

	sec *= (dev->geo.csecs >> 9);

	split = bio_split(*bio, sec, GFP_KERNEL, &pblk_bio_set);
	/* there isn't chance to merge the splitted bio */
	split->bi_opf |= REQ_NOMERGE;
	bio_set_flag(*bio, BIO_QUEUE_ENTERED);
	bio_chain(split, *bio);
	generic_make_request(*bio);
	*bio = split;
}

/* RAIL's sector mapping function */
int pblk_rail_map_page_data(struct pblk *pblk, unsigned int sentry,
			    struct ppa_addr *ppa_list,
			    unsigned long *lun_bitmap,
			    struct pblk_sec_meta *meta_list,
			    unsigned int valid_secs)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	struct pblk_emeta *emeta;
	struct pblk_w_ctx *w_ctx;
	__le64 *lba_list;
	u64 paddr;
	int nr_secs = pblk->min_write_pgs;
	int i;

	if (pblk_line_is_full(line)) {
		struct pblk_line *prev_line = line;

		/* If we cannot allocate a new line, make sure to store metadata
		 * on current line and then fail
		 */
		line = pblk_line_replace_data(pblk);
		pblk_line_close_meta(pblk, prev_line);

		if (!line)
			return -EINTR;
	}

	emeta = line->emeta;
	lba_list = emeta_to_lbas(pblk, emeta->buf);

	paddr = pblk_alloc_page(pblk, line, nr_secs);

	for (i = 0; i < nr_secs; i++, paddr++) {
		__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

		/* ppa to be sent to the device */
		ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);

		/* Write context for target bio completion on write buffer. Note
		 * that the write buffer is protected by the sync backpointer,
		 * and a single writer thread have access to each specific entry
		 * at a time. Thus, it is safe to modify the context for the
		 * entry we are setting up for submission without taking any
		 * lock or memory barrier.
		 */
		if (i < valid_secs) {
			kref_get(&line->ref);

			WARN_ON(!pblk_rail_valid_sector(pblk, line, paddr));

			if (sentry & PBLK_RAIL_PARITY_WRITE) {
				u64 *lba;
				int slot = sentry & ~PBLK_RAIL_PARITY_WRITE;

				lba = &pblk->rail.lba[slot + i];
				meta_list[i].lba = cpu_to_le64(*lba);
				lba_list[paddr] = cpu_to_le64(*lba);
				line->nr_valid_lbas++;
				continue;
			}
			if ((i % pblk->min_write_pgs) == 0)
				pblk_rail_track_sec(pblk, line, paddr,
						    sentry + i, valid_secs);

			w_ctx = pblk_rb_w_ctx(&pblk->rwb, sentry + i);
			w_ctx->ppa = ppa_list[i];
			meta_list[i].lba = cpu_to_le64(w_ctx->lba);
			lba_list[paddr] = cpu_to_le64(w_ctx->lba);
			if (lba_list[paddr] != addr_empty)
				line->nr_valid_lbas++;
			else
				atomic64_inc(&pblk->pad_wa);
		} else {
			lba_list[paddr] = meta_list[i].lba = addr_empty;
			__pblk_map_invalidate(pblk, line, paddr);
		}
	}

	pblk_down_rq(pblk, ppa_list, nr_secs, lun_bitmap);
	return 0;
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

void pblk_rail_line_close(struct pblk *pblk, struct pblk_line *line)
{
	int off, bit;

	/* Mark RAIL parity sectors as bad sectors so they will be gc'ed */
	for (off = pblk_rail_dsec_per_stripe(pblk);
	     off < pblk->lm.sec_per_line;
	     off += pblk_rail_sec_per_stripe(pblk)) {
		for (bit = 0; bit < pblk_rail_psec_per_stripe(pblk); bit++)
			set_bit(off + bit, line->invalid_bitmap);
	}
}

void pblk_rail_end_io_write(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	if (rqd->error) {
		pblk_log_write_err(pblk, rqd);
		return pblk_end_w_fail(pblk, rqd);
	}
#ifdef CONFIG_NVM_DEBUG
	else
		WARN_ONCE(rqd->bio->bi_status, "pblk: corrupted write error\n");
#endif

	pblk_up_rq(pblk, rqd->ppa_list, rqd->nr_ppas, c_ctx->lun_bitmap);

	pblk_put_rqd_kref(pblk, rqd);
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
	int nr_data = PBLK_RAIL_STRIDE_WIDTH - 1;
	struct pblk_line *line = pblk_line_get_data(pblk);

	c_ctx->nr_valid = nr_secs;
	/* sentry indexes rail page buffer, instead of rwb */
	c_ctx->sentry = stride * pblk->min_write_pgs;
	c_ctx->sentry |= PBLK_RAIL_PARITY_WRITE;

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

			if(!pblk_rail_valid_sector(pblk, line, cur))
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
		 * read, to avoid reading parity from the bad block */
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

			return -NVM_IO_ERR;
		}
	}

	return 0;
}

/* Tracks where a sector is located in the rwb */
void pblk_rail_track_sec(struct pblk *pblk, struct pblk_line *line, int cur_sec,
			 int sentry, int nr_valid)
{
	int stride, idx, pos;

	stride = pblk_rail_sec_to_stride(pblk, cur_sec);
	idx = pblk_rail_sec_to_idx(pblk, cur_sec);
	pos = pblk_rb_wrap_pos(&pblk->rwb, sentry);
	pblk->rail.p2b[stride][idx].pos = pos;
	pblk->rail.p2b[stride][idx].nr_valid = nr_valid;
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

	/* Re-use allocated memory for intermediate lbas */
	lba_list_mem = (((void *)rqd->ppa_list) + pblk_dma_ppa_size);
	lba_list_media = (((void *)rqd->ppa_list) + 2 * pblk_dma_ppa_size);

	for (i = 0; i < rqd->nr_ppas; i++)
		lba_list_media[i] = meta_list[i].lba;
	for (i = 0; i < nr_secs; i++)
		meta_list[i].lba = lba_list_mem[i];

	for (i = 0; i < nr_secs; i++) {
		int line_id = pblk_ppa_to_line(rqd->ppa_list[rail_ppa]);
		u64 meta_lba = 0x0UL, mlba;
		struct pblk_line *line = &pblk->lines[line_id];

		valid = bitmap_weight(pr_ctx->bitmap, PBLK_RAIL_STRIDE_WIDTH);
		bitmap_shift_right(pr_ctx->bitmap, pr_ctx->bitmap,
				   PBLK_RAIL_STRIDE_WIDTH, PR_BITMAP_SIZE);

		if (valid == 0) /* Skip cached reads */
			continue;

		kref_put(&line->ref, pblk_line_put_wq);

		dst_bv = bio->bi_io_vec[bio_init_idx + i];
		dst_p = kmap_atomic(dst_bv.bv_page);

		memset(dst_p + dst_bv.bv_offset, 0, PBLK_EXPOSED_PAGE_SIZE);
		meta_list[i].lba = cpu_to_le64(0x0UL);

		for (r = 0; r < valid; r++, rail_ppa++) {
			src_bv = new_bio->bi_io_vec[rail_ppa];

			if (lba_list_media[rail_ppa] != cpu_to_le64(ADDR_EMPTY))
			{
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
	struct pblk_line *line;
	unsigned int i;
	int ppas = *nr_rail_ppas;
	int valid = 0;

	for (i = 1; i < PBLK_RAIL_STRIDE_WIDTH; i++) {
		unsigned int neighbor, lun, chnl;
		int laddr;

		neighbor = pblk_rail_wrap_lun(pblk, lun_pos + i * strides);

		lun = pblk_pos_to_lun(geo, neighbor);
		chnl = pblk_pos_to_chnl(geo, neighbor);
		pblk_dev_ppa_set_lun(pblk, &rail_ppa, lun);
		pblk_dev_ppa_set_chnl(pblk, &rail_ppa, chnl);
		if(pblk_rail_lun_busy(pblk, rail_ppa))
		  printk(KERN_EMERG "HAH luns busy %i lunpos %i\n", neighbor, lun_pos); 
		line = &pblk->lines[pblk_ppa_to_line(rail_ppa)];
		laddr = pblk_dev_ppa_to_line_addr(pblk, rail_ppa);

		/* Do not read from bad blocks */
		if (!pblk_rail_valid_sector(pblk, line, laddr)) {
			/* Perform regular read if parity sector is bad */
			if (neighbor >= pblk_rail_nr_data_luns(pblk))
				return 0;

			/* If any other neighbor is bad we can just skip it */
			continue;
		}
		//		printk(KERN_EMERG "READ lunpos %i niegh %i\n", lun_pos, neighbor);
		//print_ppa(pblk,&rail_ppa, "read " , i);
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
				 int ppa, struct ppa_addr *rail_ppa_list,
				 int *nr_rail_ppas, unsigned long *read_bitmap,
				 unsigned long *pvalid, int *rail_reads) {
	unsigned char valid;

	if (test_bit(ppa, read_bitmap))
		return;

	if (pblk_rail_lun_busy(pblk, ppa_list[ppa]) &&
	    pblk_rail_setup_ppas(pblk, ppa_list[ppa],
				 rail_ppa_list, &valid,
				 nr_rail_ppas, rail_reads)) {
		WARN_ON(test_and_set_bit(ppa, read_bitmap));
		bitmap_set(pvalid, ppa * PBLK_RAIL_STRIDE_WIDTH, valid);
	}
	else {

	  struct nvm_tgt_dev *dev = pblk->dev;
	  struct nvm_geo *geo = &dev->geo;
	  int pos = pblk_ppa_to_pos(geo, ppa_list[ppa]);
	  struct pblk_lun *rlun = &pblk->luns[pos];	  
	  if(down_trylock(&rlun->wr_sem)) {
	    printk(KERN_EMERG "huh trylock worked busy %i\n", pblk_rail_lun_busy(pblk, ppa_list[ppa]));
	    //up(&rlun->wr_sem);
	  }
	  else
	    up(&rlun->wr_sem);

	  
		rail_ppa_list[(*nr_rail_ppas)++] = ppa_list[ppa];
		bitmap_set(pvalid, ppa * PBLK_RAIL_STRIDE_WIDTH, 1);
	}
}

int pblk_rail_read_bio(struct pblk *pblk, struct nvm_rq *rqd, int blba,
		       unsigned long *read_bitmap, int bio_init_idx,
		       struct bio **bio)
{
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_pr_ctx *pr_ctx;
	struct ppa_addr rail_ppa_list[NVM_MAX_VLBA];
	DECLARE_BITMAP(pvalid, PR_BITMAP_SIZE);
	int nr_secs = rqd->nr_ppas;
	bool read_empty = bitmap_empty(read_bitmap, nr_secs);
	int nr_rail_ppas = 0, rail_reads = 0;
	int i;
	int ret;

	/* Fully cached reads should not enter this path */
	WARN_ON(bitmap_full(read_bitmap, nr_secs));

	bitmap_zero(pvalid, PR_BITMAP_SIZE);
	if (rqd->nr_ppas == 1) {
		pblk_rail_set_bitmap(pblk, &rqd->ppa_addr, 0, rail_ppa_list,
				     &nr_rail_ppas, read_bitmap, pvalid,
				     &rail_reads);

		if (nr_rail_ppas == 1) {
			memcpy(&rqd->ppa_addr, rail_ppa_list,
			       nr_rail_ppas * sizeof(struct ppa_addr));
		}
		else {
			rqd->ppa_list = rqd->meta_list + pblk_dma_meta_size;
			rqd->dma_ppa_list = rqd->dma_meta_list +
			  pblk_dma_meta_size;
			memcpy(rqd->ppa_list, rail_ppa_list,
			       nr_rail_ppas * sizeof(struct ppa_addr));
		}
	}
	else {
		for (i = 0; i < rqd->nr_ppas; i++) {
			pblk_rail_set_bitmap(pblk, rqd->ppa_list, i,
					     rail_ppa_list, &nr_rail_ppas,
					     read_bitmap, pvalid, &rail_reads);

			/* Don't split if this it the last ppa of the rqd */
			if (((nr_rail_ppas + PBLK_RAIL_STRIDE_WIDTH) >=
			     NVM_MAX_VLBA) && (i + 1 < rqd->nr_ppas)) {
				struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);

				pblk_rail_bio_split(pblk, bio, i + 1);
				rqd->nr_ppas = pblk_get_secs(*bio);
				r_ctx->private = *bio;
				break;
			}
		}
		memcpy(rqd->ppa_list, rail_ppa_list,
		       nr_rail_ppas * sizeof(struct ppa_addr));
	}

	if (bitmap_empty(read_bitmap, rqd->nr_ppas)) {
		return NVM_IO_REQUEUE;
	}

	if (read_empty && !bitmap_empty(read_bitmap, rqd->nr_ppas))
		bio_advance(*bio, (rqd->nr_ppas) * PBLK_EXPOSED_PAGE_SIZE);

	if (pblk_setup_partial_read(pblk, rqd, bio_init_idx, read_bitmap,
				    nr_rail_ppas))
		return NVM_IO_ERR;

	rqd->end_io = pblk_rail_end_io_read;
	pr_ctx = r_ctx->private;
	bitmap_copy(pr_ctx->bitmap, pvalid, PR_BITMAP_SIZE);

	ret = pblk_submit_io(pblk, rqd);
	if (ret) {
		bio_put(rqd->bio);
		pr_err("pblk: partial RAIL read IO submission failed\n");
		/* Free allocated pages in new bio */
		pblk_bio_free_pages(pblk, rqd->bio, 0, rqd->bio->bi_vcnt);
		kfree(pr_ctx);
		__pblk_end_io_read(pblk, rqd, false);
		return NVM_IO_ERR;
	}

	return NVM_IO_OK;
}

/* Notify readers that LUN is serving high latency operation */
static void pblk_rail_notify_reader_down(struct pblk *pblk, int lun)
{
	WARN_ON(test_and_set_bit(lun, pblk->rail.busy_bitmap));
	smp_mb__after_atomic();
}

static void pblk_rail_notify_reader_up(struct pblk *pblk, int lun)
{

	WARN_ON(!test_and_clear_bit(lun, pblk->rail.busy_bitmap));
	smp_mb__after_atomic();
}

int pblk_rail_lun_busy(struct pblk *pblk, struct ppa_addr ppa)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int lun_pos = pblk_ppa_to_pos(geo, ppa);

	return test_bit(lun_pos, pblk->rail.busy_bitmap);
}

/* Per stripe semaphore, enforces one writer per stripe */
int pblk_rail_down_stride(struct pblk *pblk, int lun_pos, int timeout)
{
  int strides = pblk_rail_nr_parity_luns(pblk);//pblk_rail_sec_per_stripe(pblk) / PBLK_RAIL_STRIDE_WIDTH;
	int stride = lun_pos % strides;
	int ret;

	ret = down_timeout(&pblk->rail.stride_sem[stride], timeout);
	pblk_rail_notify_reader_down(pblk, lun_pos);
	//printk(KERN_EMERG "writer lunpos %i str %i strds %i\n", lun_pos, stride, strides);
	
	return ret;
}

void pblk_rail_up_stride(struct pblk *pblk, int lun_pos)
{
  int strides = pblk_rail_nr_parity_luns(pblk);//pblk_rail_sec_per_stripe(pblk) / PBLK_RAIL_STRIDE_WIDTH;
	int stride = lun_pos % strides;

	pblk_rail_notify_reader_up(pblk, lun_pos);

	return up(&pblk->rail.stride_sem[stride]);
}

/* Determine whether a sector holds data, meta or is bad*/
bool pblk_rail_valid_sector(struct pblk *pblk, struct pblk_line *line, int pos)
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

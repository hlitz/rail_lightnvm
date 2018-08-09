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

static void __pblk_nvm_rq_clone(struct nvm_rq *clone, struct nvm_rq *rqd)
{
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_g_ctx *cloned_r_ctx = nvm_rq_to_pdu(clone);

	clone->dev = rqd->dev;
	clone->bio = rqd->bio;
	clone->ppa_addr = rqd->ppa_addr;
	clone->ppa_list = rqd->ppa_list;
	clone->end_io = rqd->end_io;
	clone->opcode = rqd->opcode;
	clone->nr_ppas = rqd->nr_ppas;
	clone->flags = rqd->flags;
	clone->ppa_status = rqd->ppa_status;
	clone->error = rqd->error;
	clone->private = rqd->private;

	cloned_r_ctx->private = r_ctx->private;
	cloned_r_ctx->start_time = r_ctx->start_time;
	cloned_r_ctx->lba = r_ctx->lba;

	//clone->nr_ppas = 
	//	clone->bio = r_ctx->private;
	/*
	if (r_ctx->private) {
		struct pblk_pr_ctx *pr_ctx = r_ctx->private;

		clone->bio = pr_ctx->orig_bio;
		clone->nr_ppas = pr_ctx->orig_nr_secs;
		}*/
}

static struct nvm_rq *pblk_nvm_rq_clone(struct pblk *pblk, struct nvm_rq *rqd,
					int type, gfp_t gfp_mask)
{
	struct nvm_rq *cloned_rqd;
	struct nvm_tgt_dev *dev = pblk->dev;

	cloned_rqd = pblk_alloc_rqd(pblk, type);

	cloned_rqd->meta_list = nvm_dev_dma_alloc(dev->parent, gfp_mask,
						  &cloned_rqd->dma_meta_list);
	if (!cloned_rqd->meta_list) {
		pr_err("pblk: not able to allocate ppa list\n");
		goto fail_rqd_free;
	}

	__pblk_nvm_rq_clone(cloned_rqd, rqd);
	return cloned_rqd;

fail_rqd_free:
	pblk_free_rqd(pblk, cloned_rqd, PBLK_READ);
	return NULL;
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
	  pr_err("pblk: unsupported RAIL stride width %i\n", lm->blk_per_line);
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

int pblk_rail_read_to_bio(struct pblk *pblk, struct nvm_rq *rqd,
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
			lba_src = le64_to_cpu(w_ctx->lba);

			if (sec < pblk->rail.p2b[stride][i].nr_valid &&
			    lba_src != cpu_to_le64(ADDR_EMPTY)) {
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

		pblk_rail_read_to_bio(pblk, rqd, bio, stride, pblk->min_write_pgs, i);

		if (pblk_submit_io_set(pblk, rqd)) {
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
static void __pblk_rail_end_io_read(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct nvm_rq *orig_rqd;
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_pr_ctx *pr_ctx = r_ctx->private;
	struct pblk_pr_ctx *chained_ctx = pr_ctx->rail.chained_ctx;
	struct bio *rail_bio = rqd->bio;
	struct bio *orig_bio;
	struct pblk_sec_meta *meta_list;
	struct bio_vec src_bv, dst_bv;
	__le64 *lba_list_mem, *lba_list_media;
	void *src_p, *dst_p;
	int i, hole, n_idx = 0;
	int orig_ppa = 0;
	int bio_init_idx;
	int nr_secs = pr_ctx->orig_nr_secs;

	if (chained_ctx) {
		orig_rqd = chained_ctx->rqd;
		orig_bio = chained_ctx->orig_bio;
		bio_init_idx = chained_ctx->bio_init_idx;
	}
	else {
		orig_rqd = rqd;
		orig_bio = pr_ctx->orig_bio;
		bio_init_idx = pr_ctx->bio_init_idx;
	}

	meta_list = orig_rqd->meta_list;

	if (unlikely(rqd->nr_ppas == 1)) {
		struct ppa_addr ppa;

		ppa = rqd->ppa_addr;
		rqd->ppa_list = pr_ctx->ppa_ptr;
		rqd->dma_ppa_list = pr_ctx->dma_ppa_list;
		rqd->ppa_list[0] = ppa;
	}

	/* Re-use allocated memory for intermediate lbas */
	lba_list_mem = (((void *)orig_rqd->ppa_list) + pblk_dma_ppa_size);
	lba_list_media = (((void *)rqd->ppa_list) + 2 * pblk_dma_ppa_size);

	for (i = 0; i < rqd->nr_ppas; i++)
		lba_list_media[i] = ((struct pblk_sec_meta *)rqd->meta_list)[i].lba;

	/* Only restore meta_list if not already restored by a partial read */
	if (!chained_ctx)
		for (i = 0; i < nr_secs; i++)
			meta_list[i].lba = lba_list_mem[i];

	i = 0;
	hole = find_first_bit(pr_ctx->bitmap, nr_secs);
	do {
		int line_id = pblk_ppa_to_line(rqd->ppa_list[orig_ppa]);
		struct pblk_line *line = &pblk->lines[line_id];
		int r;
		__le64 check_lba = cpu_to_le64(0x0UL);

		kref_put(&line->ref, pblk_line_put_wq);

		orig_ppa += pr_ctx->rail.pvalid[i];

		dst_bv = orig_bio->bi_io_vec[bio_init_idx + hole];
		dst_p = kmap_atomic(dst_bv.bv_page);

		memset(dst_p + dst_bv.bv_offset, 0, PBLK_EXPOSED_PAGE_SIZE);

		for (r = 0; r < pr_ctx->rail.pvalid[i]; r++, n_idx++) {
			src_bv = rail_bio->bi_io_vec[n_idx];

			if (lba_list_media[n_idx] != cpu_to_le64(ADDR_EMPTY)) {
				src_p = kmap_atomic(src_bv.bv_page);
				pblk_rail_data_parity(dst_p + dst_bv.bv_offset,
						      src_p + src_bv.bv_offset);
				pblk_rail_lba_parity(&check_lba,
						     &lba_list_media[n_idx]);
				kunmap_atomic(src_p);
			}

			mempool_free(src_bv.bv_page, &pblk->page_bio_pool);
		}

		kunmap_atomic(dst_p);

		if (!chained_ctx)
			meta_list[hole].lba = cpu_to_le64(check_lba);
		else{
		  BUG_ON(cpu_to_le64(check_lba) != lba_list_mem[hole]);
			WARN(cpu_to_le64(check_lba) != lba_list_mem[hole],
			     "RAIL LBA check failed %llx vs %llx\n",
			     cpu_to_le64(check_lba), lba_list_mem[hole]);
		}
		i++;
		hole = find_next_bit(pr_ctx->bitmap, PBLK_MAX_REQ_ADDRS,
				     hole + 1);
	} while (hole < nr_secs);

	bio_put(rail_bio);
	r_ctx->private = NULL;

	/* If this rqd is chained, end original bio as part of the partial read */
	if (pr_ctx->rail.chained_ctx) {
		kref_put(&pr_ctx->rail.chained_ctx->pr.ref, pblk_read_put_pr_ctx);
		pblk_free_rqd(pblk, rqd, PBLK_READ);
	}
	else {
		rqd->nr_ppas = pr_ctx->orig_nr_secs;
		bio_endio(orig_bio);
		rqd->bio = NULL;
		__pblk_end_io_read(pblk, rqd, false);
	}

	kfree(pr_ctx);
}

static void pblk_rail_end_io_read(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;

	__pblk_rail_end_io_read(pblk, rqd);
}

/* Converts original ppa into ppa list of RAIL reads */
static int pblk_rail_setup_ppas(struct pblk *pblk, struct ppa_addr ppa,
				struct ppa_addr *rail_ppas, unsigned char *pvalid,
				int *nr_rail_ppas, int *rail_reads)
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

	if (unlikely(ppas + PBLK_RAIL_STRIDE_WIDTH > PBLK_MAX_REQ_ADDRS))
		return 0;

	for (i = 1; i < PBLK_RAIL_STRIDE_WIDTH; i++) {
		unsigned int neighbor, lun, chnl;
		int laddr;

		neighbor = pblk_rail_wrap_lun(pblk, lun_pos + i * strides);

		lun = pblk_pos_to_lun(geo, neighbor);
		chnl = pblk_pos_to_chnl(geo, neighbor);
		pblk_dev_ppa_set_lun(pblk, &rail_ppa, lun);
		pblk_dev_ppa_set_chnl(pblk, &rail_ppa, chnl);

		line = &pblk->lines[pblk_ppa_to_line(rail_ppa)];
		laddr = pblk_dev_ppa_to_line_addr(pblk, rail_ppa);

		/* Do not read from bad blocks */
		if (!pblk_rail_valid_sector(pblk, line, laddr)) {
			/* Perform regular read if parity sector is bad */
			if (neighbor >= pblk_rail_nr_data_luns(pblk)){
				return 0;
			}

			/* If any other neighbor is bad we can just skip it */
			continue;
		}

		rail_ppas[ppas++] = rail_ppa;
		valid++;
	}

	if (valid == 1)
		return 0;

	pvalid[*rail_reads] = valid;
	*nr_rail_ppas = ppas;
	(*rail_reads)++;
	return 1;
}

int pblk_rail_setup_read(struct pblk *pblk, struct nvm_rq *rqd, int blba,
			 unsigned long *read_bitmap, int bio_init_idx,
			 struct bio *bio, struct nvm_rq **rail_rqd)
{
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	struct pblk_g_ctx *r_ctx;
	struct pblk_pr_ctx *pr_ctx;
	struct ppa_addr rail_ppa_list[PBLK_MAX_REQ_ADDRS];
	DECLARE_BITMAP(rail_bitmap, NVM_MAX_VLBA);
	unsigned char pvalid[PBLK_MAX_REQ_ADDRS];
	bool read_empty = bitmap_empty(read_bitmap, rqd->nr_ppas);
	int nr_rail_ppas = 0, rail_valid = 0;
	int i, j = 0;

	bitmap_zero(rail_bitmap, NVM_MAX_VLBA);

	if (rqd->nr_ppas == 1) {
		if (!test_bit(0, read_bitmap)) {
			if (pblk_rail_lun_busy(pblk, rqd->ppa_addr) &&
			    pblk_rail_setup_ppas(pblk, rqd->ppa_addr,
						 rail_ppa_list, pvalid,
						 &nr_rail_ppas, &rail_valid)) {
				WARN_ON(test_and_set_bit(0, rail_bitmap));
				WARN_ON(test_and_set_bit(0, read_bitmap));
				/* RAIL checks lba on read completion */
				meta_list[0].lba = cpu_to_le64(blba);
			}
		}
	}
	else {
		for (i = 0; i < rqd->nr_ppas; i++) {
			if (test_bit(i, read_bitmap))
				continue;

			if (pblk_rail_lun_busy(pblk, rqd->ppa_list[j]) &&
			    pblk_rail_setup_ppas(pblk, rqd->ppa_list[j],
						 rail_ppa_list, pvalid,
						 &nr_rail_ppas, &rail_valid)) {
				WARN_ON(test_and_set_bit(i, rail_bitmap));
				WARN_ON(test_and_set_bit(i, read_bitmap));
				/* RAIL checks lba on read completion */
				meta_list[i].lba = cpu_to_le64(blba + i);
				memmove(&rqd->ppa_list[j],
					&rqd->ppa_list[j + 1],
					(rqd->nr_ppas - j - 1) *
					sizeof(struct ppa_addr));
			}
			else {
				j++;
			}
		}
	}

	if (read_empty && !bitmap_empty(rail_bitmap, NVM_MAX_VLBA))
		bio_advance(bio, (rqd->nr_ppas) * PBLK_EXPOSED_PAGE_SIZE);

	if (bitmap_empty(rail_bitmap, NVM_MAX_VLBA)) {
		*rail_rqd = NULL;
		return 0;
	}

	/* Clone rqd if there is a chained partial read */
	if (!bitmap_empty(read_bitmap, rqd->nr_ppas) &&
	    !bitmap_full(read_bitmap, rqd->nr_ppas)) {
		*rail_rqd = pblk_nvm_rq_clone(pblk, rqd, PBLK_READ, GFP_KERNEL);
		if (!*rail_rqd)
			return -ENOMEM;
	}
	else {
		*rail_rqd = rqd;
	}

	if (nr_rail_ppas > 1) {
		(*rail_rqd)->ppa_list = (*rail_rqd)->meta_list + pblk_dma_meta_size;
		(*rail_rqd)->dma_ppa_list = (*rail_rqd)->dma_meta_list + pblk_dma_meta_size;
	}
	
	if (pblk_setup_partial_read(pblk, *rail_rqd, bio_init_idx, rail_bitmap,
				    nr_rail_ppas))
		goto fail_free_clone;

	r_ctx = nvm_rq_to_pdu(*rail_rqd);
	pr_ctx = r_ctx->private;
	memcpy(pr_ctx->rail.pvalid, pvalid, PBLK_MAX_REQ_ADDRS);
	memcpy((*rail_rqd)->ppa_list, rail_ppa_list,
	       sizeof(struct ppa_addr) * (*rail_rqd)->nr_ppas);
	(*rail_rqd)->end_io = pblk_rail_end_io_read;

	return 0;

fail_free_clone:
	pblk_free_rqd(pblk, *rail_rqd, PBLK_READ);
	return -ENOMEM;
}

int pblk_rail_submit_read(struct pblk *pblk, struct nvm_rq *rqd,
			  struct pblk_pr_ctx *chained_ctx)
{
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_pr_ctx *pr_ctx = r_ctx->private;
	int ret;

	pr_ctx->rail.chained_ctx = chained_ctx;

	ret = pblk_submit_io(pblk, rqd);
	if (ret) {
		bio_put(rqd->bio);
		pr_err("pblk: partial read IO submission failed\n");
		goto err;
	}

	return NVM_IO_OK;

err:
	pr_err("pblk: failed to perform partial read\n");

	/* Free allocated pages in new bio */
	pblk_bio_free_pages(pblk, rqd->bio, 0, rqd->bio->bi_vcnt);
	__pblk_end_io_read(pblk, rqd, false);
	return NVM_IO_ERR;
}

/* Notify readers that LUN is serving high latency operation */
static void pblk_rail_notify_reader_down(struct pblk *pblk, int lun)
{
	WARN_ON(test_and_set_bit(lun, pblk->rail.busy_bitmap));
	smp_mb__after_atomic();
}

static void pblk_rail_notify_reader_up(struct pblk *pblk, int lun)
{
	smp_mb__before_atomic();
	WARN_ON(!test_and_clear_bit(lun, pblk->rail.busy_bitmap));
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
	int strides = pblk_rail_sec_per_stripe(pblk) / PBLK_RAIL_STRIDE_WIDTH;
	int stride = lun_pos % strides;
	int ret;

	ret = down_timeout(&pblk->rail.stride_sem[stride], timeout);
	pblk_rail_notify_reader_down(pblk, lun_pos);

	return ret;
}

void pblk_rail_up_stride(struct pblk *pblk, int lun_pos)
{
	int strides = pblk_rail_sec_per_stripe(pblk) / PBLK_RAIL_STRIDE_WIDTH;
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

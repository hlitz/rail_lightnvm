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

unsigned int pblk_rail_enabled(struct pblk *pblk)
{
  	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	return geo->rail_stride_width > 0;
}

unsigned int pblk_rail_nr_parity_luns(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	if (!pblk_rail_enabled(pblk))
		return 0;
		
	return lm->blk_per_line / geo->rail_stride_width;
}

unsigned int pblk_rail_nr_data_luns(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;

	return lm->blk_per_line - pblk_rail_nr_parity_luns(pblk);
}

unsigned int pblk_rail_sec_per_stripe(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;

	return lm->blk_per_line * pblk->min_write_pgs;
}

unsigned int pblk_rail_psec_per_stripe(struct pblk *pblk)
{
	unsigned int pluns = pblk_rail_nr_parity_luns(pblk);
	unsigned int psecs = pluns * pblk->min_write_pgs; 

	return psecs;
}

unsigned int pblk_rail_dsec_per_stripe(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	return (geo->rail_stride_width - 1) *
	  pblk_rail_psec_per_stripe(pblk);
}

/* Wraps around luns * channels */
unsigned int pblk_rail_wrap_lun(struct pblk *pblk, unsigned int lun)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	
	return (lun & (geo->all_luns - 1));
}

/* Sem count is a shared variable but as RAIL is only best effort we don't lock
 * it on the read path for performance reasons
 */
int pblk_rail_lun_busy(struct pblk *pblk, struct ppa_addr ppa)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int lun_pos = pblk_ppa_to_pos(geo, ppa);
	int ret = 0;

	if (geo->rail_stride_width) {
		ret = test_bit(lun_pos, pblk->rail.busy_bitmap);
		if (ret > 0)
			pblk->rail.rail_reads++;

		pblk->rail.reads++;
	}

	return ret;
}

int pblk_rail_luns_busy(struct pblk *pblk, int lun_id)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int i;
	unsigned int strides = pblk_rail_nr_parity_luns(pblk);
	int ret;

	for (i = 0; i < geo->rail_stride_width; i++) {
		unsigned int neighbor;

		neighbor = pblk_rail_wrap_lun(pblk, lun_id + i * strides);
		if (neighbor == lun_id)
			continue;

		/* Javier: This is the clean version. However we do not really need to
		 * obtain the sema, a load_aquire is sufficient - please advise
		 * Also, in theory it should be sufficient to check only the previous
		 * lun in the stride as luns are always obtained sequentially */
		/*if (smp_load_acquire(&pblk->luns[neighbor].wr_sem.count) == 0) {
			return 1;
		}
		*/
		ret = down_timeout(&pblk->luns[neighbor].wr_sem, msecs_to_jiffies(30000));
		if (ret) {
			switch (ret) {
			case -ETIME:
				pr_err("pblk rail: stride semaphore timed out\n");
				return 1;
			case -EINTR:
				pr_err("pblk rail: stride semaphore timed out\n");
				return 1;
			}
		}
		up(&pblk->luns[neighbor].wr_sem);
	}

	return 0;
} 

unsigned int pblk_rail_sec_to_stride(struct pblk *pblk, unsigned int sec)
{
	unsigned int sec_in_stripe = sec % pblk_rail_sec_per_stripe(pblk); 
	int page = sec_in_stripe / pblk->min_write_pgs;

	return page % pblk_rail_nr_parity_luns(pblk);
}

unsigned int pblk_rail_sec_to_idx(struct pblk *pblk, unsigned int sec)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	unsigned int sec_in_stripe = sec % pblk_rail_sec_per_stripe(pblk); 
	int distance = (geo->all_luns / geo->rail_stride_width)
			  * pblk->min_write_pgs;

	return sec_in_stripe / distance;
}

/* Returns the stripe the line's cur_sec is in */
unsigned int pblk_rail_cur_stripe(struct pblk *pblk)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	unsigned int sec = line->cur_sec;

	return sec >> get_count_order(pblk_rail_sec_per_stripe(pblk));
}

/* Checks whether we have to schedule parity writes */
int pblk_rail_sched_parity(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_line *line = pblk_line_get_data(pblk);
	unsigned int sec_in_stripe;

	if (!geo->rail_stride_width)
		return 0;

	while (1) {
		sec_in_stripe = line->cur_sec % pblk_rail_sec_per_stripe(pblk);

		/* Schedule parity write at end of data section */
		if (sec_in_stripe == pblk_rail_dsec_per_stripe(pblk))
			return 1;

		/* Skip bad blocks and meta sectors until we find a valid sec
		 * As we always write min_write_pgs sectors this will guarantee
		 * that either */
		if (test_bit(line->cur_sec, line->map_bitmap))
			line->cur_sec += pblk->min_write_pgs;
		else
			break;
	}

	return 0;
}

int pblk_rail_init(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	unsigned int i, p2be;
	unsigned int nr_strides;
	unsigned int psecs;
	void *kaddr;

	if (geo->rail_stride_width == 0) {
		pblk->rail.enabled = 0;
		return 0;
	}

	if (((geo->all_luns % geo->rail_stride_width) != 0) ||
	    (geo->all_luns < geo->rail_stride_width)) {
		pr_err("pblk: unsupported RAIL stride width\n");
		return -EINVAL;
	}

	psecs = pblk_rail_psec_per_stripe(pblk);
	nr_strides = pblk_rail_dsec_per_stripe(pblk) / 
		(geo->rail_stride_width - 1);

	pblk->rail.p2b = kmalloc(nr_strides * sizeof(struct p2b_entry *),
				    GFP_KERNEL);
	if (!pblk->rail.p2b)
		return -ENOMEM;

	for (p2be = 0; p2be < nr_strides; p2be++) {
		int e;
		
		pblk->rail.p2b[p2be] = kmalloc((geo->rail_stride_width - 1) *
					       sizeof(struct p2b_entry),
					       GFP_KERNEL);
		if (!pblk->rail.p2b[p2be])
			goto free_p2b_entries;

		for (e = 0; e < geo->rail_stride_width - 1; e++) {
			pblk->rail.p2b[p2be][e].pos = PBLK_RAIL_EMPTY;
			pblk->rail.p2b[p2be][e].nr_valid = ~0x0;
		}
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

	pblk->rail.prev_rq_line = NULL;
	pblk->rail.prev_nr_secs = 0;
	pblk->rail.enabled = (PBLK_RAIL_WRITE | PBLK_RAIL_ERASE);
	pblk->rail.busy_bitmap = kzalloc(DIV_ROUND_UP(lm->blk_per_line,
						      BITS_PER_LONG) *
					 sizeof(unsigned long), GFP_KERNEL);
	if (!pblk->rail.busy_bitmap)
		goto free_lba;

	printk(KERN_EMERG "Initialized RAIL with stride width %d\n",
	       geo->rail_stride_width);

	return 0;

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

void pblk_rail_tear_down(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	unsigned int i;
	unsigned int nr_strides;
	unsigned int psecs;

	if (geo->rail_stride_width == 0)
		return;

	psecs = pblk_rail_psec_per_stripe(pblk);
	nr_strides = pblk_rail_dsec_per_stripe(pblk) /
		(geo->rail_stride_width - 1);

	kfree(pblk->rail.lba);
	free_pages((unsigned long)page_address(pblk->rail.pages),
		   get_count_order(psecs));
	kfree(pblk->rail.data);
	for (i = 0; i < nr_strides; i++)
		kfree(pblk->rail.p2b[i]);
	kfree(pblk->rail.p2b);
}

void pblk_rail_data_parity(void *dest, void *src)
{
	unsigned int i;

	for (i = 0; i < PBLK_EXPOSED_PAGE_SIZE / sizeof(unsigned long); i++)
		((unsigned long *)dest)[i] ^= ((unsigned long *)src)[i];
}

void pblk_rail_lba_parity(u64 *dest, u64 *src)
{
	*dest ^= *src;
}

void pblk_rail_end_parity_write(struct pblk *pblk, struct nvm_rq *rqd,
				struct pblk_c_ctx *c_ctx)
{
	pblk_read_put_rqd_kref(pblk, rqd);
	bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, PBLK_WRITE);
}

int pblk_rail_read_to_bio(struct pblk *pblk, struct nvm_rq *rqd,
			  struct bio *bio, unsigned int stride,
			  unsigned int nr_secs, unsigned int paddr)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	int sec, i;
	int nr_data = geo->rail_stride_width - 1;
	struct pblk_line *line = pblk_line_get_data(pblk);

	c_ctx->nr_valid = nr_secs;
	c_ctx->is_rail = true;
	/* sentry indexes rail page buffer, instead of rwb */
	c_ctx->sentry = stride * pblk->min_write_pgs;

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
			int distance = (geo->all_luns / geo->rail_stride_width)
			  * pblk->min_write_pgs;

			if (!test_bit(paddr + sec - distance * (nr_data - i),
				      line->rail_bitmap)) {
				unsigned int pos;
				struct pblk_w_ctx *w_ctx;
				u64 lba_src;
				struct pblk_rb_entry *entry;

				pos = pblk->rail.p2b[stride][i].pos;
				pos = pblk_rb_wrap_pos(&pblk->rwb, pos + sec);
				entry = &pblk->rwb.entries[pos];
				w_ctx = &entry->w_ctx;
				lba_src = le64_to_cpu(w_ctx->lba);
				if (lba_src == ADDR_EMPTY)
					continue;

				pblk_rail_data_parity(pg_addr, entry->data);
				pblk_rail_lba_parity(lba, &lba_src);
			}
		}
	}

	return 0;
}

int pblk_rail_submit_write(struct pblk *pblk)
{
	int stripe = pblk_rail_cur_stripe(pblk);
	int i;
	struct nvm_rq *rqd;
	struct bio *bio;
	struct pblk_line *line = pblk_line_get_data(pblk);
	int start = line->cur_sec;
	static int last_stripe = ~0x0;
	unsigned int stride = 0;

	BUG_ON(last_stripe == stripe);
	last_stripe = stripe;

	for (i = start; i < start + pblk_rail_psec_per_stripe(pblk);
	     i += pblk->min_write_pgs, stride++) {
		/* Do not generate parity in this slot if the sec is bad
		 * or reserved for meta.
		 * We check on the read path and perform a conventional
		 * read, to avoid reading parity from the bad block */
		if (test_bit(i, line->rail_bitmap))
			continue;

		/* This only happens when emeta secs extend into the parity
		 * region in the last stride of a line */
		if (!line->rail_parity_secs)
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

		if (pblk_submit_io_set(pblk, rqd, true)) {
			bio_put(rqd->bio);
			pblk_free_rqd(pblk, rqd, PBLK_WRITE);

			return 1;
		}
	}

	return 0;
}

void pblk_rail_track_sec(struct pblk *pblk, struct pblk_line *line, int cur_sec,
			 int nr_valid, int sentry) 
{
	int stride = pblk_rail_sec_to_stride(pblk, cur_sec);
	int idx = pblk_rail_sec_to_idx(pblk, cur_sec);
	int pos = pblk_rb_wrap_pos(&pblk->rwb, sentry);

	pblk->rail.p2b[stride][idx].pos = pos;
	pblk->rail.p2b[stride][idx].nr_valid = nr_valid;
}

/* Read Path */
static void __pblk_rail_end_io_read(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *rail_bio = rqd->bio;
	struct bio *orig_bio = r_ctx->private;
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	struct bio_vec src_bv, dst_bv;
	__le64 *lba_list_mem, *lba_list_media;
	void *src_p, *dst_p;
	int i, hole, n_idx = 0;
	int orig_ppa = 0;
	__le64 addr_empty = cpu_to_le64(ADDR_EMPTY);

	if (unlikely(rqd->nr_ppas == 1)) {
		struct ppa_addr ppa;

		ppa = rqd->ppa_addr;
		rqd->ppa_list = r_ctx->ppa_ptr;
		rqd->dma_ppa_list = r_ctx->dma_ppa_list;
		rqd->ppa_list[0] = ppa;
	}

	/* Re-use allocated memory for intermediate lbas */
	lba_list_mem = (((void *)rqd->ppa_list) + pblk_dma_ppa_size);
	lba_list_media = (((void *)rqd->ppa_list) + 2 * pblk_dma_ppa_size);
	for (i = 0; i < rqd->nr_ppas; i++)
		lba_list_media[i] = meta_list[i].lba;
	for (i = 0; i < r_ctx->nr_orig_secs; i++)
		meta_list[i].lba = lba_list_mem[i];

	i = 0;
	hole = find_first_bit(&r_ctx->bitmap, PBLK_MAX_REQ_ADDRS);
	do {
		int line_id = pblk_ppa_to_line(rqd->ppa_list[orig_ppa]);
		struct pblk_line *line = &pblk->lines[line_id];
		int r;

		kref_put(&line->ref, pblk_line_put_wq);

		meta_list[hole].lba = 0;
		orig_ppa += r_ctx->pvalid[i];

		dst_bv = orig_bio->bi_io_vec[r_ctx->bio_init_idx + hole];
		dst_p = kmap_atomic(dst_bv.bv_page);

		memset(dst_p + dst_bv.bv_offset, 0, PBLK_EXPOSED_PAGE_SIZE);
		WARN_ON(dst_bv.bv_offset);
		for (r = 0; r < r_ctx->pvalid[i]; r++) {
			src_bv = rail_bio->bi_io_vec[n_idx];
			src_p = kmap_atomic(src_bv.bv_page);

			if(lba_list_media[n_idx] != addr_empty) {
				pblk_rail_data_parity(dst_p + dst_bv.bv_offset,
							 src_p + src_bv.bv_offset);
				pblk_rail_lba_parity(&meta_list[hole].lba,
						     &lba_list_media[n_idx]);
			}
			kunmap_atomic(src_p);
			mempool_free(src_bv.bv_page, pblk->page_bio_pool);
			n_idx++;
		}

		kunmap_atomic(dst_p);
		i++;
		hole = find_next_bit(&r_ctx->bitmap, PBLK_MAX_REQ_ADDRS,
					  hole + 1);
	} while (i < r_ctx->nr_orig_secs_as_rail);

	bio_put(rail_bio);
	r_ctx->private = NULL;
	bio_endio(orig_bio);
	rqd->bio = orig_bio;
	rqd->nr_ppas = r_ctx->nr_orig_secs;

	return __pblk_end_io_read(pblk, rqd, false);
}

static void pblk_rail_end_io_read(struct nvm_rq *rqd)
{
	struct pblk *pblk = rqd->private;

	__pblk_rail_end_io_read(pblk, rqd);
}

/* Converts original ppa into ppa list of RAIL reads */
int pblk_rail_setup_ppas(struct pblk *pblk, struct ppa_addr ppa,
			 struct ppa_addr *rail_ppas, unsigned char *pvalid)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	unsigned int lun_pos = pblk_ppa_to_pos(geo, ppa);
	unsigned int strides = pblk_rail_nr_parity_luns(pblk);
	struct pblk_line *line;
	unsigned int i;
	int ppas = 0;

	for (i = 1; i < geo->rail_stride_width; i++) {
		unsigned int neighbor, lun, chnl;

		neighbor = pblk_rail_wrap_lun(pblk, lun_pos + i * strides);

		lun = pblk_pos_to_lun(geo, neighbor);
		chnl = pblk_pos_to_chnl(geo, neighbor);
		pblk_dev_ppa_set_lun(&ppa, lun);
		pblk_dev_ppa_set_chnl(&ppa, chnl);

		line = &pblk->lines[pblk_ppa_to_line(ppa)];
		
		/* Do not read from bad blocks */
		if (test_bit(pblk_dev_ppa_to_line_addr(pblk, ppa), 
			     line->rail_bitmap)) {
			/* We cannot recompute the original sec if parity is bad */
			if (neighbor >= pblk_rail_nr_data_luns(pblk)){
				*pvalid = 0; 
				return 0;
			}

			/* If any other neighbor is bad we can just skip it */
			continue;
		}

		if (test_bit(neighbor, line->blk_bitmap)) {
			printk(KERN_EMERG "hmm shoudl nt this be caught\n");
			continue;
		}

		rail_ppas[ppas++] = ppa;
		(*pvalid)++; /* Valid (non-bb/meta) reads in stride */
	}

	/* Dont do RAIL-read if all neighbors are bad */
	return *pvalid > 0;
}

int pblk_rail_read_bio(struct pblk *pblk, struct nvm_rq *rqd,
		       unsigned int bio_init_idx, unsigned long *read_bitmap,
		       struct ppa_addr *rail_ppa_list, unsigned char *pvalid)
{
	struct bio *new_bio, *bio = rqd->bio;
	struct pblk_sec_meta *meta_list = rqd->meta_list;
	int nr_orig_secs_as_rail = bitmap_weight(read_bitmap, PBLK_MAX_REQ_ADDRS);
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	unsigned char nr_holes = 0;
	__le64 *lba_list_mem;
	int i, ret;

	/* Re-use allocated memory for intermediate lbas */
	lba_list_mem = (((void *)rqd->ppa_list) + pblk_dma_ppa_size);
	for (i = 0; i < r_ctx->nr_orig_secs; i++)
		lba_list_mem[i] = meta_list[i].lba;

	for (i = 0; i < nr_orig_secs_as_rail; i++)
		nr_holes += pvalid[i];
	
	new_bio = bio_alloc(GFP_KERNEL, nr_holes);

	if (pblk_bio_add_pages(pblk, new_bio, GFP_KERNEL, nr_holes, false))
		goto err;

	if (nr_holes != new_bio->bi_vcnt) {
		pr_err("pblk: malformed bio\n");
		goto err_pages;
	}

	new_bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(new_bio, REQ_OP_READ, 0);

	rqd->bio = new_bio;
	rqd->nr_ppas = nr_holes;
	rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);
	rqd->end_io = pblk_rail_end_io_read;
	rqd->private = pblk;

	memcpy(rqd->ppa_list, rail_ppa_list, sizeof(struct ppa_addr) * nr_holes);
	r_ctx->ppa_ptr = NULL;

	if (unlikely(nr_holes == 1)) {
		r_ctx->ppa_ptr = rqd->ppa_list;
		r_ctx->dma_ppa_list = rqd->dma_ppa_list;
		rqd->ppa_addr = rqd->ppa_list[0];
	}

	WARN_ON(rqd->nr_ppas < 1 || rqd->nr_ppas > 64);
	ret = pblk_submit_read_io(pblk, rqd);
	if (ret) {
		bio_put(rqd->bio);
		pr_err("pblk: RAIL read IO submission failed\n");
		goto err_pages;
	}

	return NVM_IO_OK;
	
err_pages:
	pblk_bio_free_pages(pblk, bio, 0, new_bio->bi_vcnt);
err:
	bio_put(new_bio);

	return NVM_IO_ERR;
}

/* Per stripe semaphore, enforces one writer per stripe */
void pblk_rail_down_stripe(struct pblk *pblk, int lun, int access_type)
{
	int timeout = 0;
	
	if (access_type & pblk->rail.enabled) {
		while (pblk_rail_luns_busy(pblk, lun)) {
			timeout++;
			if (timeout >= 10000000) {
				printk(KERN_EMERG " timeout down rail lun busy\n");
				break;
			}
		}
	}
}

/* Notify readers that LUN is serving high latency operation */
void pblk_rail_notify_reader_down(struct pblk *pblk, int lun, int access_type)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	bool gc_only = pblk->rail.enabled & PBLK_RAIL_GC_ONLY;

	if (gc_only && !(access_type & PBLK_RAIL_GC_ONLY))
		return;

	if (geo->rail_stride_width && (access_type & pblk->rail.enabled))
		WARN_ON(test_and_set_bit(lun, pblk->rail.busy_bitmap));
}

void pblk_rail_notify_reader_up(struct pblk *pblk, int lun)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	if (geo->rail_stride_width)
		clear_bit(lun, pblk->rail.busy_bitmap);
}

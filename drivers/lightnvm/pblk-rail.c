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
	return pblk->rail.stride_width > 0;
}

unsigned int pblk_rail_nr_parity_luns(struct pblk *pblk)
{
	struct pblk_line_meta *lm = &pblk->lm;

	if (pblk_rail_enabled(pblk))
		return lm->blk_per_line / pblk->rail.stride_width;

	return 0;
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
	unsigned int dsecs;
  
	dsecs = (pblk->rail.stride_width - 1) *
		pblk_rail_psec_per_stripe(pblk);
	
	BUG_ON(dsecs != pblk_rail_sec_per_stripe(pblk) - pblk_rail_psec_per_stripe(pblk));
	return dsecs;
}

unsigned int pblk_rail_stripe_bad_psecs(struct pblk *pblk, int stripe)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	unsigned int byte_offset;
	unsigned char * parity_bitmap;

	byte_offset = (stripe * pblk_rail_sec_per_stripe(pblk) +
		       pblk_rail_dsec_per_stripe(pblk)) >> BYTE_SHIFT;
	parity_bitmap = (unsigned char *)line->map_bitmap + byte_offset;

	BUG_ON(byte_offset > (pblk->lm.sec_per_line >> BYTE_SHIFT));

	return bitmap_weight((unsigned long *)parity_bitmap, 
			     pblk_rail_psec_per_stripe(pblk));
}

unsigned int pblk_rail_stripe_good_psecs(struct pblk *pblk, int stripe)
{
	unsigned int secs = pblk_rail_psec_per_stripe(pblk);
	unsigned int bad_secs = pblk_rail_stripe_bad_psecs(pblk, stripe);
	if((secs-bad_secs) !=32)
		printk(KERN_EMERG "good secs only %d stripe %d\n", secs-bad_secs, stripe);
	BUG_ON(((secs-bad_secs)%4)!=0);
	return secs - bad_secs;
}

unsigned int pblk_rail_wrap_lun(struct pblk *pblk, unsigned int lun)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	return (lun & (geo->nr_luns - 1));
}

/* Sem count is a shared variable but as RAIL is only best effort we don't lock
 * it on the read path for performance reasons
 */
int pblk_rail_lun_busy(struct pblk *pblk, struct ppa_addr ppa)
{
	int lun_id = pblk_dev_ppa_to_lun(ppa);

	return smp_load_acquire(&pblk->luns[lun_id].wr_sem.count) == 0;
} 

int pblk_rail_luns_busy(struct pblk *pblk, int lun_id)
{
	int i;
	int busy = 0;
	unsigned int strides = pblk_rail_nr_parity_luns(pblk);

	for (i = 0; i < pblk->rail.stride_width; i++) {
		unsigned int neighbor;

		neighbor = pblk_rail_wrap_lun(pblk, lun_id + i * strides);
		if (neighbor == lun_id)
			continue;
		
		if (smp_load_acquire(&pblk->luns[neighbor].wr_sem.count) == 0)
			busy = 1;
	}

	return busy;
} 

unsigned int pblk_rail_sec_to_stride(struct pblk *pblk, unsigned int sec)
{
	//printk(KERN_EMERG "sec %d / %d all %d\n", sec , sec / pblk->min_write_pgs, (sec % (pblk_rail_psec_per_stripe(pblk) * pblk->min_write_pgs)) / pblk->min_write_pgs);
	return (sec % pblk_rail_psec_per_stripe(pblk)) / pblk->min_write_pgs ;
}

unsigned int pblk_rail_sec_to_idx(struct pblk *pblk, unsigned int sec)
{
	//printk(KERN_EMERG " for bug %d %d %d\n", sec, pblk_rail_psec_per_stripe(pblk), pblk->rail.stride_width);
	//BUG_ON(sec / pblk_rail_psec_per_stripe(pblk) >= pblk->rail.stride_width);
	
	unsigned int sec_in_stripe = sec % pblk_rail_sec_per_stripe(pblk); 
	//printk(KERN_EMERG "sec to idz %d\n", sec_in_stripe / pblk_rail_psec_per_stripe(pblk));
	return sec_in_stripe / pblk_rail_psec_per_stripe(pblk);
}

/* Returns the stripe the line's cur_sec is in */
unsigned int pblk_rail_cur_stripe(struct pblk *pblk)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	unsigned int sec = line->cur_sec;
	//printk(KERN_EMERG "sec %d stripe %d\n", sec, sec >> get_count_order(pblk_rail_sec_per_stripe(pblk)));
	BUG_ON((sec >> get_count_order(pblk_rail_sec_per_stripe(pblk)) > pblk->lm.sec_per_line / pblk_rail_sec_per_stripe(pblk)));
	return sec >> get_count_order(pblk_rail_sec_per_stripe(pblk));
}

int pblk_rail_stripe_open(struct pblk *pblk, unsigned int sec)
{
	return (sec % pblk_rail_sec_per_stripe(pblk) == 0);
}

int pblk_rail_sched_parity(struct pblk *pblk)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	unsigned int sec_in_stripe;
	
	while (1) {
		sec_in_stripe = line->cur_sec % pblk_rail_sec_per_stripe(pblk);
		//printk(KERN_EMERG "sec in s %d dsec %d\n", sec_in_stripe, pblk_rail_dsec_per_stripe(pblk));
		if (sec_in_stripe == pblk_rail_dsec_per_stripe(pblk))
			return 1;
	
		if (test_bit(line->cur_sec, line->map_bitmap))
			line->cur_sec += pblk->min_write_pgs;
		else
			break;
	}

	return 0;
}
		
int pblk_rail_init(struct pblk *pblk)
{
	unsigned int i;
	unsigned int nr_strides;
	unsigned int psecs;
	void *kaddr;
	
	/* Set rail stride with as the very first thing */
	pblk->rail.stride_width = 4;

	psecs = pblk_rail_psec_per_stripe(pblk);

	nr_strides = pblk_rail_dsec_per_stripe(pblk) / 
		(pblk->rail.stride_width - 1);

	pblk->rail.sec2rb = kmalloc(nr_strides * sizeof(unsigned int *), 
				    GFP_KERNEL);
	
	for (i = 0; i < nr_strides; i++) {
		pblk->rail.sec2rb[i] = kmalloc(pblk->rail.stride_width * 
					       sizeof(unsigned int), GFP_KERNEL);
		memset(pblk->rail.sec2rb[i], 0, pblk->rail.stride_width * 
		       sizeof(unsigned int));
	}

	pblk->rail.data = kmalloc(psecs * sizeof(void *), GFP_KERNEL);
	pblk->rail.pages = alloc_pages(GFP_KERNEL, get_count_order(psecs));
	kaddr = page_address(pblk->rail.pages);
	
	for (i = 0; i < psecs; i++) {
		pblk->rail.data[i] = kaddr + (i * pblk->rwb.seg_size);
	}

	pblk->rail.prev_rq_line = NULL;
	pblk->rail.prev_nr_secs = 0;

	printk(KERN_EMERG "kaddr %p pages %p\n", kaddr, pblk->rail.pages);
	printk(KERN_EMERG "page res %p\n", virt_to_page(kaddr));
	
	return 0;
}

void pblk_rail_tear_down(struct pblk *pblk)
{
	unsigned int i;
	unsigned int nr_strides;
	unsigned int psecs = pblk_rail_psec_per_stripe(pblk);

	if (pblk->rail.prev_rq_line) 
		for (i = 0; i < pblk->rail.prev_nr_secs; i++) 
			kref_put(&pblk->rail.prev_rq_line->ref, pblk_line_put);

	nr_strides = pblk_rail_dsec_per_stripe(pblk) / 
		(pblk->rail.stride_width - 1);	

	for (i = 0; i < nr_strides; i++)
                kfree(pblk->rail.sec2rb[i]);

	kfree(pblk->rail.sec2rb);
	kfree(pblk->rail.data);
	free_pages((unsigned long)page_address(pblk->rail.pages), 
		   get_count_order(psecs));
}


void pblk_rail_compute_parity(void *dest, void *src)
{
	unsigned int i;
	
	for (i = 0; i < PBLK_EXPOSED_PAGE_SIZE / sizeof(unsigned long); i++) {
		*(unsigned long *)dest ^=
			*(unsigned long *)src; 
	}
}

void pblk_rail_end_parity_write(struct pblk *pblk, struct nvm_rq *rqd, 
				struct pblk_c_ctx *c_ctx)
{
	struct nvm_tgt_dev *dev = pblk->dev;

	nvm_dev_dma_free(dev->parent, rqd->meta_list, rqd->dma_meta_list);
	
	bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, WRITE);
}

int pblk_rail_read_to_bio(struct pblk *pblk, struct nvm_rq *rqd, 
			  struct bio *bio, unsigned int nr_secs)
{
	unsigned int psec;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	c_ctx->nr_valid = nr_secs;
	c_ctx->is_rail = true;

	/* Put line refs of the previous RAIL request */
	if (pblk->rail.prev_rq_line) 
		for (psec = 0; psec < pblk->rail.prev_nr_secs; psec++) 
			kref_put(&pblk->rail.prev_rq_line->ref, pblk_line_put);

	pblk->rail.prev_nr_secs = 0;
	
	for (psec = 0; psec < nr_secs; psec++) {
		int stride, sec, i;
		void *page_addr = pblk->rail.data[psec];
		struct page *page;

		page = virt_to_page(page_addr);
		if (!page) {
			pr_err("pblk: could not allocate RAIL bio page %p\n", page_addr);
			return -NVM_IO_ERR;
		}

		if (bio_add_page(bio, page, pblk->rwb.seg_size, 0) !=
		    pblk->rwb.seg_size) {
			pr_err("pblk: could not add page to RAIL bio\n");
			return -NVM_IO_ERR;
		}

		stride = psec / pblk->min_write_pgs;
		sec = psec % pblk->min_write_pgs;

		memset(page_addr, 0, PAGE_SIZE);
		for (i = 0; i < pblk->rail.stride_width - 1; i++) {
			/* Skip bad data sectors */
			if (pblk->rail.sec2rb[stride][i] != PBLK_RAIL_BAD_SEC) {
				unsigned int pos; 
				void *rb_addr;
				
				pos = pblk->rail.sec2rb[stride][i] + sec;
				rb_addr = pblk->rwb.entries[pos].data;
				pblk_rail_compute_parity(page_addr, rb_addr);
			}		
		}
	}
	
	return 0;
}

int pblk_rail_submit_write(struct pblk *pblk)
{
	unsigned int good_psecs;
	int stripe;
	int i;
	struct nvm_rq *rqd;
	struct bio *bio;
	static int last_stripe = ~0x0;
	stripe = pblk_rail_cur_stripe(pblk);

	BUG_ON(last_stripe == stripe);
	last_stripe = stripe;
	good_psecs = pblk_rail_stripe_good_psecs(pblk, stripe);	     
	
	for (i = 0; i < good_psecs; i += pblk->min_write_pgs) {
		rqd = pblk_alloc_rqd(pblk, WRITE);
		if (IS_ERR(rqd)) {
			pr_err("pblk: cannot allocate parity write req.\n");
			return -ENOMEM;
		}

		bio = bio_alloc(GFP_KERNEL, pblk->min_write_pgs);
		if (!bio) {
			pr_err("pblk: cannot allocate parity write bio\n");
			pblk_free_rqd(pblk, rqd, WRITE);
			return -ENOMEM;
		}

		bio->bi_iter.bi_sector = 0; /* internal bio */
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
		rqd->bio = bio;

		pblk_rail_read_to_bio(pblk, rqd, bio, pblk->min_write_pgs);

		if (pblk_submit_io_set(pblk, rqd, true)) {
			bio_put(rqd->bio);
			pblk_free_rqd(pblk, rqd, WRITE);
			return 1;
		}
	}

	return 0;
}

static u64 __pblk_rail_alloc_page(struct pblk *pblk, struct pblk_line *line, 
			   int nr_secs, unsigned int sentry)
{
	u64 addr;
	int i, e;
	unsigned int min_secs = pblk->min_write_pgs;
	
	lockdep_assert_held(&line->lock);

	BUG_ON(nr_secs != pblk->min_write_pgs);

	/* logic error: ppa out-of-bounds. Prevent generating bad address */
	if (line->cur_sec + nr_secs > pblk->lm.sec_per_line) {
		WARN(1, "pblk: page allocation out of bounds\n");
		nr_secs = pblk->lm.sec_per_line - line->cur_sec;
	}

	/* Skip bad blocks and track them in sec2rb */
	while (1) {
		if(test_bit(line->cur_sec, line->map_bitmap)) {
			int stride = pblk_rail_sec_to_stride(pblk, line->cur_sec);
			int idx = pblk_rail_sec_to_idx(pblk, line->cur_sec);
			printk(KERN_EMERG "test bit str %d idx %d\n", stride, idx);
			pblk->rail.sec2rb[stride][idx] = PBLK_RAIL_BAD_SEC;
		}		
		else {
			break;
		}

		line->cur_sec += pblk->min_write_pgs;
	}

	addr = line->cur_sec;
	min_secs = pblk->min_write_pgs;

	/* Store rb position for later parity calculation */
	for (i = 0; i < nr_secs; i += min_secs, line->cur_sec += min_secs) {
		int stride = pblk_rail_sec_to_stride(pblk, line->cur_sec);
		int idx = pblk_rail_sec_to_idx(pblk, line->cur_sec);
		//printk(KERN_EMERG "add stuff to mapstr %d idx %d opos %d\n", stride, idx, sentry + i);
		pblk->rail.sec2rb[stride][idx] = pblk_rb_wrap_pos(&pblk->rwb, sentry + i);
		
		for (e = 0; e < min_secs; e++)
			WARN_ON(test_and_set_bit(line->cur_sec + e, line->map_bitmap));
	}

	return addr;
}

u64 pblk_rail_alloc_page(struct pblk *pblk, struct pblk_line *line, int nr_secs,
			 unsigned int sentry)
{
	u64 addr;

	/* Lock needed in case a write fails and a recovery needs to remap
	 * failed write buffer entries
	 */
	spin_lock(&line->lock);
	addr = __pblk_rail_alloc_page(pblk, line, nr_secs, sentry);
	line->left_msecs -= nr_secs;
	WARN(line->left_msecs < 0, "pblk: page allocation out of bounds\n");
	spin_unlock(&line->lock);

	return addr;
}
			
/* Read Path */

/* Converts original ppa into ppa list of RAIL reads */
int pblk_rail_setup_ppas(struct pblk *pblk, struct ppa_addr ppa,
			 struct ppa_addr *rail_ppas, unsigned char *pvalid)
{
	unsigned int blk_id = pblk_dev_ppa_to_lun(ppa);
	unsigned int strides = pblk_rail_nr_parity_luns(pblk);
	struct pblk_line *line = pblk_line_get_data(pblk);
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	unsigned int i, ppas = 0;

	for (i = 0; i < pblk->rail.stride_width; i++) {
		unsigned int neighbor, lun, chnl, log_luns;

		neighbor = pblk_rail_wrap_lun(pblk, blk_id + i * strides);
		if (neighbor == blk_id)
			continue;
		
		/* Do not read from bad blocks */
		if (test_bit(blk_id, line->blk_bitmap))
			continue;
		
		log_luns = ilog2(geo->luns_per_chnl);
		lun = neighbor & (~0 >> (sizeof(lun) - log_luns)); 
		chnl = neighbor >> log_luns;
		pblk_dev_ppa_set_lun(&ppa, lun);
		pblk_dev_ppa_set_chnl(&ppa, chnl);
		rail_ppas[ppas++] = ppa;
		(*pvalid)++; /* Valid (non-bb) reads in stride */
		printk(KERN_EMERG "neighbor %i lun %i ch %i\n", neighbor, lun, chnl);
	}

	return ppas;
}

int pblk_rail_read_bio(struct pblk *pblk, struct nvm_rq *rqd,
		       unsigned int bio_init_idx, unsigned long *read_bitmap,
		       struct nvm_rq *new_rqd, unsigned char *pvalid)
{

	struct bio *new_bio, *bio = rqd->bio;
	
	struct bio_vec src_bv, dst_bv;
	void *src_p, *dst_p;
	int nr_orig_secs = bitmap_weight(read_bitmap, rqd->nr_ppas); 
	int nr_holes = nr_orig_secs * (pblk->rail.stride_width - 1);
	int nr_secs = rqd->nr_ppas;
	int i, ret, hole, n_idx = 0;
	DECLARE_COMPLETION_ONSTACK(wait);

	new_bio = bio_alloc(GFP_KERNEL, nr_holes);
	if (!new_bio) {
		pr_err("pblk: could not alloc read bio\n");
		return NVM_IO_ERR;
	}

	if (pblk_bio_add_pages(pblk, new_bio, GFP_KERNEL, nr_holes))
		goto err;

	if (nr_holes != new_bio->bi_vcnt) {
		pr_err("pblk: malformed bio\n");
		goto err_pages;
	}

	new_bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(new_bio, REQ_OP_READ, 0);
	new_bio->bi_private = &wait;
	new_bio->bi_end_io = pblk_end_bio_sync;

	new_rqd->opcode = NVM_OP_PREAD;
	new_rqd->private = pblk;
	new_rqd->bio = new_bio;
	new_rqd->nr_ppas = nr_holes;
	new_rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);
	new_rqd->end_io = NULL;

	ret = pblk_submit_read_io(pblk, new_rqd);
	if (ret) {
		bio_put(new_rqd->bio);
		pr_err("pblk: read IO submission failed\n");
		goto err_pages;
	}

	if (!wait_for_completion_io_timeout(&wait,
				msecs_to_jiffies(PBLK_COMMAND_TIMEOUT_MS))) {
		pr_err("pblk: partial read I/O timed out\n");
	}

	if (new_rqd->error) {
		atomic_long_inc(&pblk->read_failed);
#ifdef CONFIG_NVM_DEBUG
//		pblk_print_failed_new_rqd(pblk, new_rqd, new_rqd->error);
#endif
	}

	/* Fill the holes in the original bio */
	i = 0;
	hole = find_first_bit(read_bitmap, nr_secs);
	do {
		unsigned int swidth = pblk->rail.stride_width - 1;
		int r;

		dst_bv = bio->bi_io_vec[bio_init_idx + hole];
		dst_p = kmap_atomic(dst_bv.bv_page);
		
		memset(dst_p + dst_bv.bv_offset, 0, PBLK_EXPOSED_PAGE_SIZE);

		for (r = 0; r < pvalid[i]; r++) {
			src_bv = new_bio->bi_io_vec[n_idx++];
			src_p = kmap_atomic(src_bv.bv_page);

			pblk_rail_compute_parity(dst_p + dst_bv.bv_offset,
						 src_p + src_bv.bv_offset);
			
			kunmap_atomic(src_p);
			mempool_free(src_bv.bv_page, pblk->page_pool);
		}

		kunmap_atomic(dst_p);

		i++;
		hole = find_next_zero_bit(read_bitmap, nr_secs, hole + 1);
	} while (hole < nr_orig_secs);

	bio_put(new_bio);

	return NVM_IO_OK;

err_pages:
	pblk_bio_free_pages(pblk, bio, 0, new_bio->bi_vcnt);
err:
	bio_put(new_bio);

	return NVM_IO_ERR;
}

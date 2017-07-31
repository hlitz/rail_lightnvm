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

#define PBLK_RAIL_BAD_SEC ~0x0
#define PBLK_RAIL_PADDED_SEC (PBLK_RAIL_BAD_SEC - 1)
#define BYTE_SHIFT 3

unsigned int pblk_rail_enabled(struct pblk *pblk)
{
	return pblk->rail.stride_width > 0;
}

unsigned int pblk_rail_nr_parity_luns(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	if (pblk_rail_enabled(pblk))
		return geo->nr_luns / pblk->rail.stride_width;

	return 0;
}
//TODO lun -> blk clean up
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

unsigned int pblk_rail_stripe_per_line(struct pblk *pblk)
{
	return pblk->lm.sec_per_line / pblk_rail_sec_per_stripe(pblk);
}
/*
void pblk_rail_stripe_bitmap(struct pblk *pblk, struct pblk_line *line, 
			     unsigned int stripe, unsigned long *stripe_bitmap)
{
	unsigned int stripe_size = pblk_rail_sec_per_stripe(pblk);
	
	bitmap_shift_right(stripe_bitmap, line->invalid_bitmap, 
			   stripe_size * stripe, stripe_size);
}

unsigned int pblk_rail_stripe_good_secs(struct pblk *pblk, 
					unsigned int stripe)
{
	unsigned int stripe_size = pblk_rail_sec_per_stripe(pblk);
	unsigned long stripe_bitmap[BITS_TO_LONGS(stripe_size) * sizeof(long)];
	struct pblk_line *line = pblk_line_get_data(pblk);

	pblk_rail_stripe_bitmap(pblk, line, stripe, stripe_bitmap);

	return bitmap_weight(stripe_bitmap, stripe_size);
}*/

unsigned int pblk_rail_stripe_bad_psecs(struct pblk *pblk, int stripe)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	unsigned int byte_offset;
	unsigned char * parity_bitmap;

	byte_offset = (stripe * pblk_rail_sec_per_stripe(pblk) +
		       pblk_rail_dsec_per_stripe(pblk)) >> BYTE_SHIFT;
	parity_bitmap = (unsigned char *)line->map_bitmap + byte_offset;
	//printk (KERN_EMERG "sec per line %d sec %d stripe %d line %p parmap %p off %d\n", pblk->lm.sec_per_line , line->cur_sec, stripe, line, parity_bitmap, byte_offset);

	BUG_ON(byte_offset > (pblk->lm.sec_per_line >> BYTE_SHIFT));

/*	if(bitmap_weight((unsigned long *)parity_bitmap, 
			 pblk_rail_psec_per_stripe(pblk)) != 32)
			 printk(KERN_EMERG "parity bitmap addr %p content %p perl %d offset %d ii %d %d %d \n", parity_bitmap, line->map_bitmap, pblk->lm.sec_per_line, byte_offset, stripe , pblk_rail_sec_per_stripe(pblk) , 8);*/

	return bitmap_weight((unsigned long *)parity_bitmap, 
			     pblk_rail_psec_per_stripe(pblk));
/*
	pblk_rail_stripe_bitmap(pblk, line, stripe, stripe_bitmap);
	
	bitmap_shift_right(parity_bitmap, stripe_bitmap, 
			   pblk_rail_dsec_per_stripe(pblk),
			   psecs);

			   return bitmap_weight(stripe_bitmap, psecs);*/
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

int pblk_rail_lun_busy(struct pblk *pblk, struct ppa_addr ppa)
{
	/* Unfortunately there is no API to check a semaphore value */
	return (pblk->luns[pblk_dev_ppa_to_lun(ppa)].wr_sem.count == 0);
} 

unsigned int pblk_rail_wrap_lun(struct pblk *pblk, unsigned int lun)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	return (lun & (geo->nr_luns - 1));
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
		
//if(sec_in_stripe >= pblk_rail_dsec_per_stripe(pblk))
	//	printk(KERN_EMERG "sec in st %d per s %d\n", sec_in_stripe,pblk_rail_dsec_per_stripe(pblk));
//	return sec_in_stripe >= pblk_rail_dsec_per_stripe(pblk);
//}

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
	printk(KERN_EMERG "kaddr %p pages %p\n", kaddr, pblk->rail.pages);
	printk(KERN_EMERG "page res %p\n", virt_to_page(kaddr));
	
	return 0;
}

void pblk_rail_compute_parity(void *dest, void *src)
{
	unsigned int i;
	
	for (i = 0; i < PBLK_EXPOSED_PAGE_SIZE / sizeof(unsigned long); i++) {
		*(unsigned long *)dest ^= *(unsigned long *)src; 
	}
}

void pblk_rail_end_parity_write(struct pblk *pblk, struct nvm_rq *rqd, 
				struct pblk_c_ctx *c_ctx)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_line *line = pblk_line_get_data(pblk);
	int i;

	nvm_dev_dma_free(dev->parent, rqd->meta_list, rqd->dma_meta_list);
	
	for (i = 0; i < c_ctx->nr_valid; i++)
		kref_put(&line->ref, pblk_line_put);

//	static long end = 0;
//	printk(KERN_EMERG "lin put %p %d\n", line, end++);}
	bio_put(rqd->bio);
	pblk_free_rqd(pblk, rqd, WRITE);
}

/*
void pblk_rail_map_page_parity(struct pblk *pblk, unsigned int cur_sec,
			       struct ppa_addr *ppa_list,
			       unsigned long *lun_bitmap,
			       unsigned int valid_secs)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	//struct pblk_w_ctx *w_ctx;
	u64 paddr;
	int min = pblk->min_write_pgs;
	int i;

	//for (i = 0; i < nr_secs; i++, paddr++) {
	//for (s = 0; s < strides; s++) {
	//	for (i = 0; i < idx; i++, ppa++) {
	paddr = __pblk_alloc_page(pblk, line, min);
	line->left_msecs -= min;
	WARN(line->left_msecs < 0, "pblk: page allocation out of bounds\n");
	
	for (i = 0; i < min; i++) {

		ppa_list[i] = addr_to_gen_ppa(pblk, paddr, line->id);
		kref_get(&line->ref);
//	w_ctx = pblk->rail.rb2sec[s][i];
//	w_ctx->ppa = ppa_list[ppa];
	}

	if (pblk_line_is_full(line)) {
		struct pblk_line *prev_line = line;

		pblk_line_replace_data(pblk);
		pblk_line_close_meta(pblk, prev_line);
	}

	pblk_down_rq(pblk, ppa_list, min, lun_bitmap);
}*/

int pblk_rail_read_to_bio(struct pblk *pblk, struct nvm_rq *rqd, 
			  struct bio *bio, unsigned int nr_secs)
{
	unsigned int psec;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);

	c_ctx->nr_valid = nr_secs;
	c_ctx->is_rail = true;

	for (psec = 0; psec < nr_secs; psec++) {
		int stride, sec, i;
		void *page_addr = pblk->rail.data[psec];
		struct page *page;

		page = virt_to_page(page_addr);
		if (!page) {
			pr_err("pblk: could not allocate RAIL bio page %p\n", page_addr);
			return -NVM_IO_ERR;
		}
//		printk(KERN_EMERG "add page %p \n", page);		
		if (bio_add_page(bio, page, pblk->rwb.seg_size, 0) !=
		    pblk->rwb.seg_size) {
			pr_err("pblk: could not add page to RAIL bio\n");
			return -NVM_IO_ERR;
		}

		stride = psec / pblk->min_write_pgs;
		sec = psec % pblk->min_write_pgs;
		//printk(KERN_EMERG "sec %d\n", sec);
		memset(page_addr, 0, PAGE_SIZE);
		for (i = 0; i < pblk->rail.stride_width - 1; i++) {
			/* Skip data sectors which are bad */
			if (pblk->rail.sec2rb[stride][i] != PBLK_RAIL_BAD_SEC) {
				unsigned int pos; 
				void *rb_addr;
				
				pos = pblk->rail.sec2rb[stride][i] + sec;
				rb_addr = pblk->rwb.entries[pos].data;
				pblk_rail_compute_parity(page_addr, rb_addr);
			}		
		}
/*		
		if (sec == 0) {
			pblk_rail_map_page_parity(pblk, line->cur_sec, &rqd->ppa_list[psec], 
						  lun_bitmap, pblk->min_write_pgs);
			printk(KERN_EMERG "mapped %lx\n", rqd->ppa_list[psec]);
		}
*/
	}
	
	return 0;
}

int pblk_rail_submit_write(struct pblk *pblk)
{
//	int ret = 0;
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
	static long rails = 0;
	//printk(KERN_EMERG "sumbit rail good %d\n", good_psecs, rails++);
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
	struct pblk_line *line = pblk_line_get_data(pblk);
	//xsprintk(KERN_EMERG "cur %d rb space %d\n", line->cur_sec, pblk_rb_space(&pblk->rwb));
	BUG_ON((line->cur_sec % pblk_rail_sec_per_stripe(pblk)) != 0);
	return 0;
}
/*
bool pblk_rail_parity_to_bio(pblk, rqd, bio, pos)
{
	struct pblk *pblk = container_of(rb, struct pblk, rwb);
	struct request_queue *q = pblk->dev->q;
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	struct pblk_rb_entry *entry;
	struct page *page;
	unsigned int pad = 0;
	unsigned int to_read;
	unsigned int i, base;
	int flags;

	to_read = pblk_rail_psec_per_stripe(pblk);

	stripe_valid_secs = pblk_secs_in_stripe(pblk) - 
		bitmap_weight(pblk->cur_stripe_bitmap);

	c_ctx->sentry = pos;
	c_ctx->nr_valid = to_read;
	c_ctx->nr_padded = pad;

	struct bio_vec *bv;

	// Parity computation is affected by bad blocks in three ways:
	 // 1. One of the data sectors of the stride is bad -> skip it
	 // 2. Any sector of a different stride is bad -> adjust distance
	 // 3. The parity sector is bad -> use the prior lun for parity
	 //
	unsigned int rb_idx = pos;
	for (i = 0; i < pblk_rail_dsecs_in_stripe(pblk); i++) {
		if (bitmap_set(i, pblk->cur_stripe_bitmap))
			pblk->parity_rb[i] = 0;
		else {
			pblk->parity_rb[i] = rb_idx;
			rb_idx = pblk_rb_wrap_pos(&pblk->rwb, rb_idx + 1);
		}
	} 

	bio_for_each_segment_all(bv, bio, base) { //iter over RAIL strides
		void * page_addr = page_address(bv->bv_page);
		unsigned int psecs = pblk_rail_psec_per_stripe(pblk);
		unsigned int rb_idx;

		for (rb_idx = base; rb_idx < (base + psecs); rb_idx++) {
			if (pblk->parity_rb[rb_idx])
				pblk_rail_compute_parity(page_addr, pblk->parity_rb[rb_idx]);
			
		}
	} 

	for (i = 0; i < to_read; i++) {
		entry = &rb->entries[pos];

	
try:
		flags = READ_ONCE(entry->w_ctx.flags);
		if (!(flags & PBLK_WRITTEN_DATA)) {
			io_schedule();
			goto try;
		}

		page = virt_to_page(entry->data);
		if (!page) {
			pr_err("pblk: could not allocate write bio page\n");
			flags &= ~PBLK_WRITTEN_DATA;
			flags |= PBLK_SUBMITTED_ENTRY;
	
			smp_store_release(&entry->w_ctx.flags, flags);
			return NVM_IO_ERR;
		}

		if (bio_add_pc_page(q, bio, page, rb->seg_size, 0) !=
								rb->seg_size) {
			pr_err("pblk: could not add page to write bio\n");
			flags &= ~PBLK_WRITTEN_DATA;
			flags |= PBLK_SUBMITTED_ENTRY;
	
			smp_store_release(&entry->w_ctx.flags, flags);
			return NVM_IO_ERR;
		}

		if (flags & PBLK_FLUSH_ENTRY) {
			unsigned int sync_point;

			sync_point = READ_ONCE(rb->sync_point);
			if (sync_point == pos) {
	
				smp_store_release(&rb->sync_point, EMPTY_ENTRY);
			}

			flags &= ~PBLK_FLUSH_ENTRY;
#ifdef CONFIG_NVM_DEBUG
			atomic_dec(&rb->inflight_sync_point);
#endif
		}

		flags &= ~PBLK_WRITTEN_DATA;
		flags |= PBLK_SUBMITTED_ENTRY;

	
		smp_store_release(&entry->w_ctx.flags, flags);

		pos = (pos + 1) & (rb->nr_entries - 1);
	}

	}*/

u64 __pblk_rail_alloc_page(struct pblk *pblk, struct pblk_line *line, 
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
//		BUG_ON(pblk_rail_sched_parity(pblk));
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
static void pblk_end_io_read(struct nvm_rq *rqd)
{
	/* Fill the holes in the original bio */
	i = 0;
	hole = find_first_zero_bit(read_bitmap, nr_secs);
	do {
		src_bv = new_bio->bi_io_vec[i++];
		dst_bv = bio->bi_io_vec[bio_init_idx + hole];

		src_p = kmap_atomic(src_bv.bv_page);
		dst_p = kmap_atomic(dst_bv.bv_page);

		memcpy(dst_p + dst_bv.bv_offset,
			src_p + src_bv.bv_offset,
			PBLK_EXPOSED_PAGE_SIZE);

		kunmap_atomic(src_p);
		kunmap_atomic(dst_p);

		mempool_free(src_bv.bv_page, pblk->page_pool);

		hole = find_next_zero_bit(read_bitmap, nr_secs, hole + 1);
	} while (hole < nr_secs);


	struct pblk *pblk = rqd->private;
	struct nvm_tgt_dev *dev = pblk->dev;
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *bio = rqd->bio;

	if (rqd->error)
		pblk_log_read_err(pblk, rqd);
#ifdef CONFIG_NVM_DEBUG
	else
		WARN_ONCE(bio->bi_status, "pblk: corrupted read error\n");
#endif

	nvm_dev_dma_free(dev->parent, rqd->meta_list, rqd->dma_meta_list);

	bio_put(bio);

#ifdef CONFIG_NVM_DEBUG
	atomic_long_add(rqd->nr_ppas, &pblk->sync_reads);
	atomic_long_sub(rqd->nr_ppas, &pblk->inflight_reads);
#endif

	pblk_free_rqd(pblk, rqd, READ);
	atomic_dec(&pblk->inflight_io);
}

/* Converts original ppa into ppa list of RAIL reads */
void pblk_rail_setup_ppas(struct pblk *pblk, struct ppa_addr ppa,
			  struct ppa_addr *rail_ppas)
{
	unsigned int lun_id = pblk_dev_ppa_to_lun(ppa);
	unsigned int strides = pblk_rail_nr_parity_luns(pblk);
	unsigned int i;
	printk(KERN_EMERG "orig lun %i\n", lun_id);
	for (i = 0; i < (pblk->rail.stride_width - 1); i++) {
		unsigned int neighbor;

		neighbor = pblk_rail_wrap_lun(pblk, lun_id + i * strides);
		printk(KERN_EMERG "neighbou %i\n", neighbor);
		pblk_dev_ppa_set_lun(&ppa, neighbor);
		rail_ppas[i] = ppa;
	}
}

static int pblk_rail_read_bio(struct pblk *pblk, struct nvm_rq *rqd,
				      unsigned int bio_init_idx,
				      unsigned long *read_bitmap)
{
	struct bio *new_bio, *bio = rqd->bio;
	struct bio_vec src_bv, dst_bv;
	void *ppa_ptr = NULL;
	void *src_p, *dst_p;
	dma_addr_t dma_ppa_list = 0;
	int nr_secs = rqd->nr_ppas;
	int nr_holes = nr_secs - bitmap_weight(read_bitmap, nr_secs);
	int i, ret, hole;
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
		goto err;
	}

	new_bio->bi_iter.bi_sector = 0; /* internal bio */
	bio_set_op_attrs(new_bio, REQ_OP_READ, 0);
	new_bio->bi_private = &wait;
	new_bio->bi_end_io = pblk_end_bio_sync;

	rqd->bio = new_bio;
	rqd->nr_ppas = nr_holes;
	rqd->flags = pblk_set_read_mode(pblk, PBLK_READ_RANDOM);
	rqd->end_io = NULL;

	if (unlikely(nr_secs > 1 && nr_holes == 1)) {
		ppa_ptr = rqd->ppa_list;
		dma_ppa_list = rqd->dma_ppa_list;
		rqd->ppa_addr = rqd->ppa_list[0];
	}

	ret = pblk_submit_read_io(pblk, rqd);
	if (ret) {
		bio_put(rqd->bio);
		pr_err("pblk: read IO submission failed\n");
		goto err;
	}

	if (!wait_for_completion_io_timeout(&wait,
				msecs_to_jiffies(PBLK_COMMAND_TIMEOUT_MS))) {
		pr_err("pblk: partial read I/O timed out\n");
	}

	if (rqd->error) {
		atomic_long_inc(&pblk->read_failed);
#ifdef CONFIG_NVM_DEBUG
		pblk_print_failed_rqd(pblk, rqd, rqd->error);
#endif
	}

	if (unlikely(nr_secs > 1 && nr_holes == 1)) {
		rqd->ppa_list = ppa_ptr;
		rqd->dma_ppa_list = dma_ppa_list;
	}

	/* Fill the holes in the original bio */
	i = 0;
	hole = find_first_zero_bit(read_bitmap, nr_secs);
	do {
		swidth = pblk->rail.stride_width - 1;

		dst_bv = bio->bi_io_vec[bio_init_idx + hole];
		dst_p = kmap_atomic(dst_bv.bv_page);
		memset(dst_p + dst_bv.bv_offset, 0, PBLK_EXPOSED_PAGE_SIZE);

		for (r = 0; r < swidth; r++) {
			src_bv = new_bio->bi_io_vec[i * swidth + r];
			src_p = kmap_atomic(src_bv.bv_page);

			pblk_rail_compute_parity(dst_p + dst_bv.bv_offset,
						 src_p + src_bv.bv_offset);
			
			kunmap_atomic(src_p);
		}

		kunmap_atomic(dst_p);

		mempool_free(src_bv.bv_page, pblk->page_pool);
		
		i++;
		hole = find_next_zero_bit(read_bitmap, nr_secs, hole + 1);
	} while (hole < nr_secs);

	bio_put(new_bio);

	/* Complete the original bio and associated request */
/*	rqd->bio = bio;
	rqd->nr_ppas = nr_secs;
	rqd->private = pblk;

	bio_endio(bio);
	pblk_end_io_read(rqd);*/
	return NVM_IO_OK;

err:
	/* Free allocated pages in new bio */
	pblk_bio_free_pages(pblk, bio, 0, new_bio->bi_vcnt);
	rqd->private = pblk;
	pblk_end_io_read(rqd);
	return NVM_IO_ERR;
}

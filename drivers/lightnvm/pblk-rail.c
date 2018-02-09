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

	if (!pblk_rail_enabled(pblk))
		return 0;
		
	return lm->blk_per_line / pblk->rail.stride_width;
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

	BUG_ON(dsecs != (pblk_rail_sec_per_stripe(pblk) -
			 pblk_rail_psec_per_stripe(pblk)));

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

	return secs - bad_secs;
}

/* Wraps around luns * channels */
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
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	int lun_pos = pblk_ppa_to_pos(geo, ppa);

	return smp_load_acquire(&pblk->luns[lun_pos].wr_sem.count) == 0;
}

int pblk_rail_luns_busy(struct pblk *pblk, int lun_id)
{
	int i;
	unsigned int strides = pblk_rail_nr_parity_luns(pblk);
	int ret;

	for (i = 0; i < pblk->rail.stride_width; i++) {
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
	return (sec % pblk_rail_psec_per_stripe(pblk)) / pblk->min_write_pgs ;
}

unsigned int pblk_rail_sec_to_idx(struct pblk *pblk, unsigned int sec)
{
	unsigned int sec_in_stripe = sec % pblk_rail_sec_per_stripe(pblk); 

	return sec_in_stripe / pblk_rail_psec_per_stripe(pblk);
}

/* Returns the stripe the line's cur_sec is in */
unsigned int pblk_rail_cur_stripe(struct pblk *pblk)
{
	struct pblk_line *line = pblk_line_get_data(pblk);
	unsigned int sec = line->cur_sec;

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

		/*
		if (sec_in_stripe > pblk_rail_dsec_per_stripe(pblk) &&
		    (sec_in_stripe < pblk_rail_sec_per_stripe(pblk))){
		  printk(KERN_EMERG "in railcur sec %i sec ins %i ds %i s %i\n",
			 line->cur_sec, sec_in_stripe,
			 pblk_rail_dsec_per_stripe(pblk),
			 pblk_rail_sec_per_stripe(pblk));
		  WARN_ON(1);
		  }*/
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
	unsigned int i;
	unsigned int nr_strides;
	unsigned int psecs;
	void *kaddr;

	/* Set rail stride with as the very first thing */
	pblk->rail.stride_width = 4;

	psecs = pblk_rail_psec_per_stripe(pblk);

	nr_strides = pblk_rail_dsec_per_stripe(pblk) / 
		(pblk->rail.stride_width - 1);

	pblk->rail.sec2rb = kmalloc(nr_strides * sizeof(struct sec2rb_entry *),
				    GFP_KERNEL);

	for (i = 0; i < nr_strides; i++) {
		int e;
		
		pblk->rail.sec2rb[i] = kmalloc((pblk->rail.stride_width - 1) *
					       sizeof(struct sec2rb_entry),
					       GFP_KERNEL);
		for (e = 0; e < pblk->rail.stride_width - 1; e++) {
			pblk->rail.sec2rb[i][e].pos = PBLK_RAIL_EMPTY;
			pblk->rail.sec2rb[i][e].nr_valid = ~0x0;
		}
	}

	pblk->rail.data = kmalloc(psecs * sizeof(void *), GFP_KERNEL);
	pblk->rail.pages = alloc_pages(GFP_KERNEL, get_count_order(psecs));
	kaddr = page_address(pblk->rail.pages);

	for (i = 0; i < psecs; i++)
		pblk->rail.data[i] = kaddr + i * PBLK_EXPOSED_PAGE_SIZE;

	pblk->rail.prev_rq_line = NULL;
	pblk->rail.prev_nr_secs = 0;

	printk(KERN_EMERG "Initialized RAIL with stride width %d\n",
			pblk->rail.stride_width);

	return 0;
}

void pblk_rail_tear_down(struct pblk *pblk)
{
	unsigned int i;
	unsigned int nr_strides;
	unsigned int psecs = pblk_rail_psec_per_stripe(pblk);

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

	for (i = 0; i < PBLK_EXPOSED_PAGE_SIZE; i++) {
		((unsigned char*)dest)[i] ^= ((unsigned char *)src)[i];

	}
//	printk(KERN_EMERG "\n");
	return;

	for (i = 0; i < PBLK_EXPOSED_PAGE_SIZE / sizeof(unsigned long); i++) {
		((unsigned long *)dest)[i] ^=
			((unsigned long *)src)[i];
	}
}

void pblk_rail_stride_put(struct kref *ref)
{
	struct rail_stride *stride = container_of(ref, struct rail_stride, ref);
	struct pblk_line *line = stride->line;
	struct pblk *pblk = line->pblk;
	unsigned long flags;
	int pos, ret;

	/* Delayed sync of all writes of the current rail stride */ 
	pos = pblk_rb_sync_init(&pblk->rwb, &flags);
	ret = pblk_rb_sync_advance(&pblk->rwb, stride->valid_secs);
	pblk_rb_sync_end(&pblk->rwb, &flags);
	WARN_ON(ret != pblk_rb_wrap_pos(&pblk->rwb, pos + stride->valid_secs));

	return;
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
	struct pblk_c_ctx *c_ctx = nvm_rq_to_pdu(rqd);
	int sec, i;
	struct pblk_line *line = pblk_line_get_data(pblk);

	c_ctx->nr_valid = nr_secs;
	c_ctx->is_rail = true;

	for (sec = 0; sec < pblk->min_write_pgs; sec++) {
		void *pg_addr;
		struct page *page;

		pg_addr = pblk->rail.data[stride * pblk->min_write_pgs + sec];
		page = virt_to_page(pg_addr);

		if (!page) {
			pr_err("pblk: could not allocate RAIL bio page %p\n", pg_addr);
			return -NVM_IO_ERR;
		}

		if (bio_add_page(bio, page, pblk->rwb.seg_size, 0) !=
		    pblk->rwb.seg_size) {
			pr_err("pblk: could not add page to RAIL bio\n");
			return -NVM_IO_ERR;
		}

		memset(pg_addr, 0, PBLK_EXPOSED_PAGE_SIZE);

		for (i = 0; i < pblk->rail.stride_width - 1; i++) {
			if (!test_bit(paddr - 32 * (pblk->rail.stride_width - 1 - i), line->rail_bitmap)
			    && sec < pblk->rail.sec2rb[stride][i].nr_valid) {
				unsigned int pos;
				void *addr;

				pos = pblk->rail.sec2rb[stride][i].pos;
				pos = pblk_rb_wrap_pos(&pblk->rwb, pos + sec);
				addr = pblk->rwb.entries[pos].data;
				pblk_rail_compute_parity(pg_addr, addr);
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

		WARN_ON(test_bit(i, line->rail_bitmap));
		/* This only happens when emeta secs extend into the parity
		 * region in the last stride of a line */
		if (!line->rail_parity_secs) {
			WARN_ON (!test_bit(i, line->invalid_bitmap));
			continue;
		}

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

	pblk->rail.sec2rb[stride][idx].pos = pos;
	pblk->rail.sec2rb[stride][idx].nr_valid = nr_valid;
}

/* Read Path */
static void __pblk_rail_end_io_read(struct pblk *pblk, struct nvm_rq *rqd)
{
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	struct bio *rail_bio = rqd->bio;
	struct bio *orig_bio = r_ctx->private;
	struct bio_vec src_bv, dst_bv;
	void *src_p, *dst_p;
	int i, hole, n_idx = 0;
	int ttt=0;
	int orig_ppa = 0;
/*	static long blub = 0;
	blub++;
	if(blub >= 680){
		int e;
		printk(KERN_EMERG "blub %lu\n", blub);
		for (e=0; e<rqd->nr_ppas; e++)
			print_ppa(&rqd->ppa_list[e], "rail read", 777);
	
			}*/
	if (rqd->error) {
		int e;
		/* Remove this crap after no read errros appear */

		//	  printk(KERN_EMERG "HMM RAIL ERROR rqd %p addr %lx bio secs %i ppa %i read line %p write line %p\n", rqd, rqd->ppa_status, pblk_get_secs(rail_bio), rqd->nr_ppas, &pblk->lines[pblk_tgt_ppa_to_line(rqd->ppa_list[0])], pblk_line_get_data(pblk));
		//pblk_print_failed_rqd(pblk, rqd, rqd->error);
		//for (e=0; e<rqd->nr_ppas; e++)
		//	print_ppa(&rqd->ppa_list[e], "rail read", 777);
		return __pblk_end_io_read(pblk, rqd, false);
	}
	if (unlikely(rqd->nr_ppas == 1)) {
		struct ppa_addr ppa;

		ppa = rqd->ppa_addr;
		rqd->ppa_list = r_ctx->ppa_ptr;
		rqd->dma_ppa_list = r_ctx->dma_ppa_list;
		rqd->ppa_list[0] = ppa;
	}

	i = 0;
	hole = find_first_bit(&r_ctx->bitmap, PBLK_MAX_REQ_ADDRS);
	do {
		int line_id = pblk_dev_ppa_to_line(rqd->ppa_list[orig_ppa]);
		struct pblk_line *line = &pblk->lines[line_id];
		int r;

		kref_put(&line->ref, pblk_line_put_wq);
		orig_ppa += r_ctx->pvalid[i];

		dst_bv = orig_bio->bi_io_vec[r_ctx->bio_init_idx + hole];
		dst_p = kmap_atomic(dst_bv.bv_page);

		memset(dst_p + dst_bv.bv_offset, 0, PBLK_EXPOSED_PAGE_SIZE);
		WARN_ON(dst_bv.bv_offset);
		for (r = 0; r < r_ctx->pvalid[i]; r++) {
			src_bv = rail_bio->bi_io_vec[n_idx++];
			src_p = kmap_atomic(src_bv.bv_page);

			pblk_rail_compute_parity(dst_p + dst_bv.bv_offset,
						 src_p + src_bv.bv_offset);
			WARN_ON(src_bv.bv_offset);
			kunmap_atomic(src_p);
			mempool_free(src_bv.bv_page, pblk->page_bio_pool);
			ttt++;
/*			if(blub >= 680){
				printk(KERN_EMERG "src %lu dst %lu\n", ((unsigned long *)src_p)[0], ((unsigned long *)dst_p)[0]);
				printk(KERN_EMERG "src %lu dst %lu\n", ((unsigned long *)src_p)[1], ((unsigned long *)dst_p)[2]);
				printk(KERN_EMERG "src %lu dst %lu\n", ((unsigned long *)src_p)[2], ((unsigned long *)dst_p)[2]);
				}*/
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
	unsigned int i, ppas = 0;

	for (i = 1; i < pblk->rail.stride_width; i++) {
		unsigned int neighbor, lun, chnl;

		neighbor = pblk_rail_wrap_lun(pblk, lun_pos + i * strides);

		lun = pblk_pos_to_lun(geo, neighbor);
		chnl = pblk_pos_to_chnl(geo, neighbor);
		pblk_dev_ppa_set_lun(&ppa, lun);
		pblk_dev_ppa_set_chnl(&ppa, chnl);

		line = &pblk->lines[pblk_dev_ppa_to_line(ppa)];
		
		/* Do not read from bad blocks */
		if (test_bit(pblk_dev_ppa_to_line_addr(pblk, ppa), 
			     line->rail_bitmap)) {
			/* We cannot recompute the original sec if parity is bad */
			if (neighbor >= pblk_rail_nr_data_luns(pblk))
				return 0;

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

	/* Dont do rail if pvalid == 1, fix RAIL to support nr_ppas == 1 */
	return *pvalid > 0;
}

int pblk_rail_read_bio(struct pblk *pblk, struct nvm_rq *rqd,
		       unsigned int bio_init_idx, unsigned long *read_bitmap,
		       struct ppa_addr *rail_ppa_list, unsigned char *pvalid)
{
	struct bio *new_bio, *bio = rqd->bio;
	int nr_orig_secs_as_rail = bitmap_weight(read_bitmap, PBLK_MAX_REQ_ADDRS);
	struct pblk_g_ctx *r_ctx = nvm_rq_to_pdu(rqd);
	unsigned char nr_holes = 0;
	DECLARE_COMPLETION_ONSTACK(wait);
	int i, ret;

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
		//for (i = 0; i<nr_holes; i++)
		//	print_ppa(&rqd->ppa_list[i], "rail read fail", 44);

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

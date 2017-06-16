#include "pblk.h"

unsigned int pblk_rail_nr_strides(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	return geo->nr_luns / pblk->rail_stride_width;
}

unsigned int pblk_rail_parity_secs_per_line(struct pblk *pblk)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;
	unsigned int strides = pblk_rail_nr_strides(pblk);
	unsigned int write_secs = geo->sec_per_pl * geo->sec_per_pg;
	unsigned int parity_secs = strides * write_secs; 
	
	return parity_secs;
}

unsigned int pblk_rail_data_secs_per_line(struct pblk *pblk)
{
	unsigned int data_secs;
  
	data_secs = (pblk->rail_stride_width - 1) *
		pblk_rail_parity_secs_per_line(pblk);
	
	return data_secs;
}

int pblk_rail_lun_busy(struct pblk *pblk, struct ppa_addr ppa)
{
	return (pblk->luns[pblk_dev_ppa_to_lun(ppa)].wr_sem.count == 0);
} 

unsigned int pblk_rail_wrap_lun(struct pblk *pblk, unsigned int lun)
{
	struct nvm_tgt_dev *dev = pblk->dev;
	struct nvm_geo *geo = &dev->geo;

	return (lun & (geo->nr_luns - 1));
}

/* Returns the other LUNs part of the same RAIL stride */
void pblk_rail_lun_neighbors(struct pblk *pblk, struct ppa_addr ppa,
			     struct ppa_addr *neighbors)
{
	unsigned int lun_id = pblk_dev_ppa_to_lun(ppa);
	unsigned int strides = pblk_rail_nr_strides(pblk);
	unsigned int i;
	printk(KERN_EMERG "orig lun %i\n", lun_id);
	for (i = 0; i < (pblk->rail_stride_width - 1); i++) {
		unsigned int neighbor;

		neighbor = pblk_rail_wrap_lun(pblk, lun_id + i * strides);
		printk(KERN_EMERG "neighbou %i\n", neighbor);
		pblk_dev_ppa_set_lun(&ppa, neighbor);
		neighbors[i] = ppa;
	}
}

void pblk_rail_gen_parity(void *dest, void *src)
{
	unsigned int i;
	
	for (i = 0; i < PBLK_EXPOSED_PAGE_SIZE / sizeof(unsigned long); i++) {
		*(unsigned long *)dest ^= *(unsigned long *)src; 
	}
}
			

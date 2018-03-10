/*
 * arch/arm/mm/highmem.c -- ARM highmem support
 *
 * Author:	Nicolas Pitre
 * Created:	september 8, 2008
 * Copyright:	Marvell Semiconductors Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <asm/fixmap.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include "mm.h"

static inline void set_fixmap_pte(int idx, pte_t pte)
{
	unsigned long vaddr = __fix_to_virt(idx);
	pte_t *ptep = pte_offset_kernel(pmd_off_k(vaddr), vaddr);

	set_pte_ext(ptep, pte, 0);
	local_flush_tlb_kernel_page(vaddr);
}

static inline pte_t get_fixmap_pte(unsigned long vaddr)
{
	pte_t *ptep = pte_offset_kernel(pmd_off_k(vaddr), vaddr);

	return *ptep;
}

/*
	建立永久内核映射。
	高端内存映射，运用数组进行操作分配情况
	分配好后需要加入到hash表中
*/
void *kmap(struct page *page)
{
	might_sleep();
	//如果页框不属于高端内存
	if (!PageHighMem(page))
		return page_address(page);
	//页框确实属于高端内存
	return kmap_high(page);
}

EXPORT_SYMBOL(kmap);

void kunmap(struct page *page)
{
	BUG_ON(in_interrupt());
	if (!PageHighMem(page))
		return;
	kunmap_high(page);
}
EXPORT_SYMBOL(kunmap);

//为建立起临时内核映射
void *kmap_atomic(struct page *page)
{
	unsigned int idx;
	unsigned long vaddr;
	void *kmap;
	int type;

	/*
		current_thread_info()->preempt_count++;抢占数++
	*/
	preempt_disable();

	pagefault_disable();

	//如果不属于高端内存，直接返回页框的线性地址
	if (!PageHighMem(page))
		return page_address(page);

#ifdef CONFIG_DEBUG_HIGHMEM
	/*
	 * There is no cache coherency issue when non VIVT, so force the
	 * dedicated kmap usage for better debugging purposes in that case.
	 */
	if (!cache_is_vivt())
		kmap = NULL;
	else
#endif
		kmap = kmap_high_get(page);
	if (kmap)
		return kmap;

	/*
		type参数和CPU标识符（smp_processor_id（）函数获得）指定必须用哪个固定映射的线性地址映射请求页
	*/
	type = kmap_atomic_idx_push();
	idx = FIX_KMAP_BEGIN + type + KM_TYPE_NR * smp_processor_id();

	/*
		用页的物理地址及Present、Accessed、Read/Write和Dirty位建立该固定映射的线性地址对应的页表项
	*/
	vaddr = __fix_to_virt(idx);

	
#ifdef CONFIG_DEBUG_HIGHMEM
	/*
	 * With debugging enabled, kunmap_atomic forces that entry to 0.
	 * Make sure it was indeed properly unmapped.
	 */
	BUG_ON(!pte_none(get_fixmap_pte(vaddr)));
#endif
	/*
	 * When debugging is off, kunmap_atomic leaves the previous mapping
	 * in place, so the contained TLB flush ensures the TLB is updated
	 * with the new mapping.

	 * 刷新适当的TLB项并返回线性地址
	 */
	set_fixmap_pte(idx, mk_pte(page, kmap_prot));

	return (void *)vaddr;
}
EXPORT_SYMBOL(kmap_atomic);

void __kunmap_atomic(void *kvaddr)
{
	unsigned long vaddr = (unsigned long) kvaddr & PAGE_MASK;
	int idx, type;

	if (kvaddr >= (void *)FIXADDR_START) {
		type = kmap_atomic_idx();
		idx = FIX_KMAP_BEGIN + type + KM_TYPE_NR * smp_processor_id();

		if (cache_is_vivt())
			__cpuc_flush_dcache_area((void *)vaddr, PAGE_SIZE);
#ifdef CONFIG_DEBUG_HIGHMEM
		BUG_ON(vaddr != __fix_to_virt(idx));
		set_fixmap_pte(idx, __pte(0));
#else
		(void) idx;  /* to kill a warning */
#endif
		kmap_atomic_idx_pop();
	} else if (vaddr >= PKMAP_ADDR(0) && vaddr < PKMAP_ADDR(LAST_PKMAP)) {
		/* this address was obtained through kmap_high_get() */
		kunmap_high(pte_page(pkmap_page_table[PKMAP_NR(vaddr)]));
	}
	pagefault_enable();
	preempt_enable();
}
EXPORT_SYMBOL(__kunmap_atomic);

void *kmap_atomic_pfn(unsigned long pfn)
{
	unsigned long vaddr;
	int idx, type;
	struct page *page = pfn_to_page(pfn);

	preempt_disable();
	pagefault_disable();
	if (!PageHighMem(page))
		return page_address(page);

	type = kmap_atomic_idx_push();
	idx = FIX_KMAP_BEGIN + type + KM_TYPE_NR * smp_processor_id();
	vaddr = __fix_to_virt(idx);
#ifdef CONFIG_DEBUG_HIGHMEM
	BUG_ON(!pte_none(get_fixmap_pte(vaddr)));
#endif
	set_fixmap_pte(idx, pfn_pte(pfn, kmap_prot));

	return (void *)vaddr;
}

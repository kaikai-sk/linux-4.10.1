/*
 *  linux/arch/arm/mm/fault.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 *  Modifications for ARM processor (c) 1995-2004 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/hardirq.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/page-flags.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/perf_event.h>

#include <asm/exception.h>
#include <asm/pgtable.h>
#include <asm/system_misc.h>
#include <asm/system_info.h>
#include <asm/tlbflush.h>

#include "fault.h"

#ifdef CONFIG_MMU

#ifdef CONFIG_KPROBES
static inline int notify_page_fault(struct pt_regs *regs, unsigned int fsr)
{
	int ret = 0;

	if (!user_mode(regs)) {
		/* kprobe_running() needs smp_processor_id() */
		preempt_disable();
		if (kprobe_running() && kprobe_fault_handler(regs, fsr))
			ret = 1;
		preempt_enable();
	}

	return ret;
}
#else
static inline int notify_page_fault(struct pt_regs *regs, unsigned int fsr)
{
	return 0;
}
#endif

/*
 * This is useful to dump out the page tables associated with
 * 'addr' in mm 'mm'.
 */
void show_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;

	if (!mm)
		mm = &init_mm;

	pr_alert("pgd = %p\n", mm->pgd);
	pgd = pgd_offset(mm, addr);
	pr_alert("[%08lx] *pgd=%08llx",
			addr, (long long)pgd_val(*pgd));

	do {
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		if (pgd_none(*pgd))
			break;

		if (pgd_bad(*pgd)) {
			pr_cont("(bad)");
			break;
		}

		pud = pud_offset(pgd, addr);
		if (PTRS_PER_PUD != 1)
			pr_cont(", *pud=%08llx", (long long)pud_val(*pud));

		if (pud_none(*pud))
			break;

		if (pud_bad(*pud)) {
			pr_cont("(bad)");
			break;
		}

		pmd = pmd_offset(pud, addr);
		if (PTRS_PER_PMD != 1)
			pr_cont(", *pmd=%08llx", (long long)pmd_val(*pmd));

		if (pmd_none(*pmd))
			break;

		if (pmd_bad(*pmd)) {
			pr_cont("(bad)");
			break;
		}

		/* We must not map this if we have highmem enabled */
		if (PageHighMem(pfn_to_page(pmd_val(*pmd) >> PAGE_SHIFT)))
			break;

		pte = pte_offset_map(pmd, addr);
		pr_cont(", *pte=%08llx", (long long)pte_val(*pte));
#ifndef CONFIG_ARM_LPAE
		pr_cont(", *ppte=%08llx",
		       (long long)pte_val(pte[PTE_HWTABLE_PTRS]));
#endif
		pte_unmap(pte);
	} while(0);

	pr_cont("\n");
}
#else					/* CONFIG_MMU */
void show_pte(struct mm_struct *mm, unsigned long addr)
{ }
#endif					/* CONFIG_MMU */

/*
 * Oops.  The kernel tried to access some page that wasn't present.
 */
static void
__do_kernel_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
		  struct pt_regs *regs)
{
	/*
	 * Are we prepared to handle this kernel fault?
	 */
	if (fixup_exception(regs))
		return;

	/*
	 * No handler, we'll have to terminate things with extreme prejudice.
	 */
	bust_spinlocks(1);
	pr_alert("Unable to handle kernel %s at virtual address %08lx\n",
		 (addr < PAGE_SIZE) ? "NULL pointer dereference" :
		 "paging request", addr);

	show_pte(mm, addr);
	die("Oops", regs, fsr);
	bust_spinlocks(0);
	do_exit(SIGKILL);
}

/*
 * Something tried to access memory that isn't in our memory map..
 * User mode accesses just cause a SIGSEGV
 */
static void
__do_user_fault(struct task_struct *tsk, unsigned long addr,
		unsigned int fsr, unsigned int sig, int code,
		struct pt_regs *regs)
{
	struct siginfo si;

#ifdef CONFIG_DEBUG_USER
	if (((user_debug & UDBG_SEGV) && (sig == SIGSEGV)) ||
	    ((user_debug & UDBG_BUS)  && (sig == SIGBUS))) {
		printk(KERN_DEBUG "%s: unhandled page fault (%d) at 0x%08lx, code 0x%03x\n",
		       tsk->comm, sig, addr, fsr);
		show_pte(tsk->mm, addr);
		show_regs(regs);
	}
#endif

	tsk->thread.address = addr;
	tsk->thread.error_code = fsr;
	tsk->thread.trap_no = 14;
	si.si_signo = sig;
	si.si_errno = 0;
	si.si_code = code;
	si.si_addr = (void __user *)addr;
	force_sig_info(sig, &si, tsk);
}

void do_bad_area(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	struct task_struct *tsk = current;
	struct mm_struct *mm = tsk->active_mm;

	/*
	 * If we are in kernel mode at this point, we
	 * have no context to handle this fault with.
	 */
	if (user_mode(regs))
		__do_user_fault(tsk, addr, fsr, SIGSEGV, SEGV_MAPERR, regs);
	else
		__do_kernel_fault(mm, addr, fsr, regs);
}

#ifdef CONFIG_MMU
#define VM_FAULT_BADMAP		0x010000
#define VM_FAULT_BADACCESS	0x020000

/*
 * Check that the permissions on the VMA allow for the fault which occurred.
 * If we encountered a write fault, we must have write permission, otherwise
 * we allow any permission.
 */
static inline bool access_error(unsigned int fsr, struct vm_area_struct *vma)
{
	unsigned int mask = VM_READ | VM_WRITE | VM_EXEC;

	if (fsr & FSR_WRITE)
		mask = VM_WRITE;
	if (fsr & FSR_LNX_PF)
		mask = VM_EXEC;

	return vma->vm_flags & mask ? false : true;
}


/*
* 缺页异常主处理函数
* 
*
*/
static int __kprobes
__do_page_fault(struct mm_struct *mm, unsigned long addr, unsigned int fsr,
		unsigned int flags, struct task_struct *tsk)
{
	struct vm_area_struct *vma;
	int fault;

	/*
	    find_vma函数是从mm结构中找到一个vm_area_struct结构，
	    这个结构的vm_end值 > 参数addr， 
	    但是vm_start可能大于也可能小于，但fing_vma会尽可能找到小于的。
	    即：addr在vma这个区间中。  
	*/
	vma = find_vma(mm, addr);
	fault = VM_FAULT_BADMAP;

	/*
	   如果vma为0，那么想当于所有vma的vm_end地址都 < 参数addr，这个产生异常错误的地址  肯定是无效地址了。 
	   因为根据进程的结构，所有vm中vm_end的最大值是3G。	
	*/
	if (unlikely(!vma))
	{
		goto out;
	}
	/*
		如果vm_start>addr，说明这个异常的地址是在空洞中，
		那么则可能是在用户态的栈中出错的。则跳去 check_stack  
	*/
	if (unlikely(vma->vm_start > addr))
		goto check_stack;

	/*
	 * Ok, we have a good vm_area for this
	 * memory access, so we can handle it.
	 * 
	 * 如果上面条件都不是，那么得到的vma结构就包含 addr这个地址。有可能是malloc后出错的。 
	 * 用户态下的malloc时候，其实并不分配物理空间，只是返回一个虚拟地址，并产生一个vm_area_struct结构，
	 * 当真正要用到malloc的空间的时候，才会产生异常，在这里得到真正的物理空间。 
	 * 当然也有可能是其他原因，比如在read only的时候进行write了。  
	 */
good_area:
	if (access_error(fsr, vma)) 
	{
		/*
		* 如果是写，但是vma->vm_flag写没有set 1，说明的确是权限的问题，那么就set fault的值，退出。
		*/
		fault = VM_FAULT_BADACCESS;
		goto out;
	}

	return handle_mm_fault(vma, addr & PAGE_MASK, flags);

check_stack:
	/*
	* Don't allow expansion below FIRST_USER_ADDRESS 
	* 不允许在FIRST_USER_ADDRESS以下展开
	*
	* 检查堆栈，进行expand，扩展原来的栈的vma，
	* 然后goto good_area，去得到一个实际的物理地址。 
	*/
	if (vma->vm_flags & VM_GROWSDOWN &&
	    addr >= FIRST_USER_ADDRESS && !expand_stack(vma, addr))
	{
		goto good_area;
	}
out:
	return fault;
}

//缺页异常处理程序
//addr：当前进程执行时引起缺页的虚地址
//regs:异常时的寄存器信息
//
static int __kprobes//__kprobes调试相关
do_page_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	struct task_struct *tsk;
	struct mm_struct *mm;
	int fault, sig, code;
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY | FAULT_FLAG_KILLABLE;

	//kprobes不想钩住虚假的错误：
	//notify_page_fault函数和上面的__kprobes相对应，调试相关
	if (notify_page_fault(regs, fsr))
		return 0;

	//将出现缺页异常的进程的进程描述符赋给tsk
	tsk = current;
	//将缺页异常的内存描述符赋给mm
	mm  = tsk->mm;

	/* Enable interrupts if they were enabled in the parent context.
		如果父环境中的中断被使能，则开中断
	*/
	if (interrupts_enabled(regs))
	{
		local_irq_enable();
	}

	/*
	 * If we're in an interrupt or have no user context, we must not take the fault..
	 * 如果我们在中断中或者没有用户上下文，我们不准处理这个异常
	 */
	/*
	* 判断发生异常的，in_atomic判断是否在原子操作中：中断程序，可延迟函数，禁用内核抢占的临界区
	* !mm判断进程是否是内核线程
	*/
	if (faulthandler_disabled() || !mm)
	{
		//如果缺页发生在这些情况下，那么就要特殊处理，
		//因为这些程序都是没有用户空间的，要特殊处理
		goto no_context;
	}

	if (user_mode(regs))
		flags |= FAULT_FLAG_USER;
	if (fsr & FSR_WRITE)
		flags |= FAULT_FLAG_WRITE;

	/*
	 * As per x86, we may deadlock here.  However, since the kernel only
	 * validly references user space from well defined areas of the code,
	 * we can bug out early if this is from code which shouldn't.
	 *
	 * 根据x86，我们可能会在这里陷入僵局。 
	 * 但是，由于内核仅从代码的明确定义的区域有效地引用用户空间，
	 * 所以如果这是来自不应该的代码，我们可以提早发现问题。
	 */
	if (!down_read_trylock(&mm->mmap_sem)) {
		if (!user_mode(regs) && !search_exception_tables(regs->ARM_pc))
			goto no_context;
retry:
		down_read(&mm->mmap_sem);
	} 
	else
	{
		/*
		 * The above down_read_trylock() might have succeeded in
		 * which case, we'll have missed the might_sleep() from
		 * down_read()
		 *
		 * 上面的down_read_trylock（）可能已经成功，在这种情况下，我们会错过来自down_read（）的might_sleep（）
		 */
		might_sleep();
#ifdef CONFIG_DEBUG_VM
		if (!user_mode(regs) &&
		    !search_exception_tables(regs->ARM_pc))
			goto no_context;
#endif
	}

	fault = __do_page_fault(mm, addr, fsr, flags, tsk);

	/* If we need to retry but a fatal signal is pending, handle the
	 * signal first. We do not need to release the mmap_sem because
	 * it would already be released in __lock_page_or_retry in
	 * mm/filemap.c. 
	 *
	 * 如果我们需要重试但一个致命的信号正在等待，请首先处理信号。 
	 * 我们不需要释放mmap_sem，因为它已经在mm/filemap.c中的__lock_page_or_retry中发布。
	 */
	if ((fault & VM_FAULT_RETRY) && fatal_signal_pending(current))
		return 0;

	/*
	 * Major/minor page fault accounting is only done on the
	 * initial attempt. If we go through a retry, it is extremely
	 * likely that the page will be found in page cache at that point.
	 */

	perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS, 1, regs, addr);
	if (!(fault & VM_FAULT_ERROR) && flags & FAULT_FLAG_ALLOW_RETRY) {
		if (fault & VM_FAULT_MAJOR) {
			tsk->maj_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MAJ, 1,
					regs, addr);
		} else {
			tsk->min_flt++;
			perf_sw_event(PERF_COUNT_SW_PAGE_FAULTS_MIN, 1,
					regs, addr);
		}
		if (fault & VM_FAULT_RETRY) {
			/* Clear FAULT_FLAG_ALLOW_RETRY to avoid any risk
			* of starvation. */
			flags &= ~FAULT_FLAG_ALLOW_RETRY;
			flags |= FAULT_FLAG_TRIED;
			goto retry;
		}
	}

	up_read(&mm->mmap_sem);

	/*
	 * Handle the "normal" case first - VM_FAULT_MAJOR
	 */
	if (likely(!(fault & (VM_FAULT_ERROR | VM_FAULT_BADMAP | VM_FAULT_BADACCESS))))
	{
		/*
		* 如果fault不是上面的值。那么就是MAJOR MINOR，说明问题解决了,return 
		* 如果是上面的值，那么就还要继续
		*/
		return 0;
	}

	/*
	 * If we are in kernel mode at this point, we have no context to handle this fault with.
	 * 如果在这个点我们在内核态，我们没有处理这个异常的上下文
	 */
	if (!user_mode(regs))
	{
		/*
		* 如果是内核空间出现了页异常，并且通过__do_page_fault没有解决，
		* 那么就跳到no_context
		*/
		goto no_context;
	}

	if (fault & VM_FAULT_OOM) 
	{
		/*
		 * We ran out of memory, call the OOM killer, and return to
		 * userspace (which will retry the fault, or kill us if we
		 * got oom-killed)
		 *
		 * 我们耗尽内存，调用OOM杀手，并返回到用户空间
		 *（这将重试错误，或者如果我们被杀死的话会杀死我们）
		 */
		pagefault_out_of_memory();
		return 0;
	}

	if (fault & VM_FAULT_SIGBUS) {
		/*
		 * We had some memory, but were unable to
		 * successfully fix up this page fault.
		 *
		 * 我们有一些内存，但无法成功解决这个页面错误。
		 */
		sig = SIGBUS;
		code = BUS_ADRERR;
	} 
	else 
	{
		/*
		 * Something tried to access memory that
		 * isn't in our memory map..
		 * 试图访问不在我们的内存映射中的内存的东西
		 */
		sig = SIGSEGV;
		code = fault == VM_FAULT_BADACCESS ?
			SEGV_ACCERR : SEGV_MAPERR;
	}

	/*
	*用户态错误，发个信号，弄死进程
	*/
	__do_user_fault(tsk, addr, fsr, sig, code, regs);
	return 0;

no_context:
	/*
	* 内核错误，这个函数什么都不干，发送OOP
	*/
	__do_kernel_fault(mm, addr, fsr, regs);
	return 0;
}
#else					/* CONFIG_MMU */

static int
do_page_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	return 0;
}
#endif					/* CONFIG_MMU */


/*
 * First Level Translation Fault Handler
 *
 * We enter here because the first level page table doesn't contain
 * a valid entry for the address.
 *
 * If the address is in kernel space (>= TASK_SIZE), then we are
 * probably faulting in the vmalloc() area.
 *
 * If the init_task's first level page tables contains the relevant
 * entry, we copy the it to this task.  If not, we send the process
 * a signal, fixup the exception, or oops the kernel.
 *
 * NOTE! We MUST NOT take any locks for this case. We may be in an
 * interrupt or a critical region, and should only copy the information
 * from the master page table, nothing more.
 */
#ifdef CONFIG_MMU
static int __kprobes
do_translation_fault(unsigned long addr, unsigned int fsr,
		     struct pt_regs *regs)
{
	unsigned int index;
	pgd_t *pgd, *pgd_k;
	pud_t *pud, *pud_k;
	pmd_t *pmd, *pmd_k;

	if (addr < TASK_SIZE)
		return do_page_fault(addr, fsr, regs);

	if (user_mode(regs))
		goto bad_area;

	index = pgd_index(addr);

	pgd = cpu_get_pgd() + index;
	pgd_k = init_mm.pgd + index;

	if (pgd_none(*pgd_k))
		goto bad_area;
	if (!pgd_present(*pgd))
		set_pgd(pgd, *pgd_k);

	pud = pud_offset(pgd, addr);
	pud_k = pud_offset(pgd_k, addr);

	if (pud_none(*pud_k))
		goto bad_area;
	if (!pud_present(*pud))
		set_pud(pud, *pud_k);

	pmd = pmd_offset(pud, addr);
	pmd_k = pmd_offset(pud_k, addr);

#ifdef CONFIG_ARM_LPAE
	/*
	 * Only one hardware entry per PMD with LPAE.
	 */
	index = 0;
#else
	/*
	 * On ARM one Linux PGD entry contains two hardware entries (see page
	 * tables layout in pgtable.h). We normally guarantee that we always
	 * fill both L1 entries. But create_mapping() doesn't follow the rule.
	 * It can create inidividual L1 entries, so here we have to call
	 * pmd_none() check for the entry really corresponded to address, not
	 * for the first of pair.
	 */
	index = (addr >> SECTION_SHIFT) & 1;
#endif
	if (pmd_none(pmd_k[index]))
		goto bad_area;

	copy_pmd(pmd, pmd_k);
	return 0;

bad_area:
	do_bad_area(addr, fsr, regs);
	return 0;
}
#else					/* CONFIG_MMU */
static int
do_translation_fault(unsigned long addr, unsigned int fsr,
		     struct pt_regs *regs)
{
	return 0;
}
#endif					/* CONFIG_MMU */

/*
 * Some section permission faults need to be handled gracefully.
 * They can happen due to a __{get,put}_user during an oops.
 */
#ifndef CONFIG_ARM_LPAE
static int
do_sect_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	do_bad_area(addr, fsr, regs);
	return 0;
}
#endif /* CONFIG_ARM_LPAE */

/*
 * This abort handler always returns "fault".
 */
static int
do_bad(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	return 1;
}

struct fsr_info {
	int	(*fn)(unsigned long addr, unsigned int fsr, struct pt_regs *regs);
	int	sig;
	int	code;
	const char *name;
};

/* FSR definition */
#ifdef CONFIG_ARM_LPAE
#include "fsr-3level.c"
#else
#include "fsr-2level.c"
#endif

void __init
hook_fault_code(int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *),
		int sig, int code, const char *name)
{
	if (nr < 0 || nr >= ARRAY_SIZE(fsr_info))
		BUG();

	fsr_info[nr].fn   = fn;
	fsr_info[nr].sig  = sig;
	fsr_info[nr].code = code;
	fsr_info[nr].name = name;
}

/*
 * Dispatch a data abort to the relevant handler.
 */
asmlinkage void __exception
do_DataAbort(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	const struct fsr_info *inf = fsr_info + fsr_fs(fsr);
	struct siginfo info;

	if (!inf->fn(addr, fsr & ~FSR_LNX_PF, regs))
		return;

	pr_alert("Unhandled fault: %s (0x%03x) at 0x%08lx\n",
		inf->name, fsr, addr);
	show_pte(current->mm, addr);

	info.si_signo = inf->sig;
	info.si_errno = 0;
	info.si_code  = inf->code;
	info.si_addr  = (void __user *)addr;
	arm_notify_die("", regs, &info, fsr, 0);
}

void __init
hook_ifault_code(int nr, int (*fn)(unsigned long, unsigned int, struct pt_regs *),
		 int sig, int code, const char *name)
{
	if (nr < 0 || nr >= ARRAY_SIZE(ifsr_info))
		BUG();

	ifsr_info[nr].fn   = fn;
	ifsr_info[nr].sig  = sig;
	ifsr_info[nr].code = code;
	ifsr_info[nr].name = name;
}

asmlinkage void __exception
do_PrefetchAbort(unsigned long addr, unsigned int ifsr, struct pt_regs *regs)
{
	const struct fsr_info *inf = ifsr_info + fsr_fs(ifsr);
	struct siginfo info;

	if (!inf->fn(addr, ifsr | FSR_LNX_PF, regs))
		return;

	pr_alert("Unhandled prefetch abort: %s (0x%03x) at 0x%08lx\n",
		inf->name, ifsr, addr);

	info.si_signo = inf->sig;
	info.si_errno = 0;
	info.si_code  = inf->code;
	info.si_addr  = (void __user *)addr;
	arm_notify_die("", regs, &info, ifsr, 0);
}

/*
 * Abort handler to be used only during first unmasking of asynchronous aborts
 * on the boot CPU. This makes sure that the machine will not die if the
 * firmware/bootloader left an imprecise abort pending for us to trip over.
 */
static int __init early_abort_handler(unsigned long addr, unsigned int fsr,
				      struct pt_regs *regs)
{
	pr_warn("Hit pending asynchronous external abort (FSR=0x%08x) during "
		"first unmask, this is most likely caused by a "
		"firmware/bootloader bug.\n", fsr);

	return 0;
}

void __init early_abt_enable(void)
{
	fsr_info[FSR_FS_AEA].fn = early_abort_handler;
	local_abt_enable();
	fsr_info[FSR_FS_AEA].fn = do_bad;
}

#ifndef CONFIG_ARM_LPAE
static int __init exceptions_init(void)
{
	if (cpu_architecture() >= CPU_ARCH_ARMv6) {
		hook_fault_code(4, do_translation_fault, SIGSEGV, SEGV_MAPERR,
				"I-cache maintenance fault");
	}

	if (cpu_architecture() >= CPU_ARCH_ARMv7) {
		/*
		 * TODO: Access flag faults introduced in ARMv6K.
		 * Runtime check for 'K' extension is needed
		 */
		hook_fault_code(3, do_bad, SIGSEGV, SEGV_MAPERR,
				"section access flag fault");
		hook_fault_code(6, do_bad, SIGSEGV, SEGV_MAPERR,
				"section access flag fault");
	}

	return 0;
}

arch_initcall(exceptions_init);
#endif

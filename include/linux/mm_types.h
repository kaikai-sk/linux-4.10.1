#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/auxvec.h>
#include <linux/types.h>
#include <linux/threads.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/uprobes.h>
#include <linux/page-flags-layout.h>
#include <linux/workqueue.h>
#include <asm/page.h>
#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

struct address_space;
struct mem_cgroup;

#define USE_SPLIT_PTE_PTLOCKS	(NR_CPUS >= CONFIG_SPLIT_PTLOCK_CPUS)
#define USE_SPLIT_PMD_PTLOCKS	(USE_SPLIT_PTE_PTLOCKS && \
		IS_ENABLED(CONFIG_ARCH_ENABLE_SPLIT_PMD_PTLOCK))
#define ALLOC_SPLIT_PTLOCKS	(SPINLOCK_SIZE > BITS_PER_LONG/8)

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 *
 * The objects in struct page are organized in double word blocks in
 * order to allows us to use atomic double word operations on portions
 * of struct page. That is currently only used by slub but the arrangement
 * allows the use of atomic double word operations on the flags/mapping
 * and lru list pointers also.
 */
struct page 
{
	/* First double word block 
		一组标识。也对页框所在的管理区进行编号
	*/
	/*
	在lru算法中主要用到两个标志
	PG_active:表示此页当前是否活跃，当放到active_lru链表时被置位
	PG_referenced:表示此页最近是否被访问，每次页面访问都会被置位
	*/
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	union 
	{
		/*
			当页被插入page cache时使用。或者当页属于匿名区时使用

			最低两位用于判断类型，其他位数用于保存指向的地址
			如果为空，则该页属于交换高速缓存（swap cache，swap时会产生竞争条件，用swap cache解决）
			不为空，如果最低位为1，该页为匿名页，指向对应的anon_vma(分配时需要对齐)
			不为空，如果最低位为0，则该页为文件页，指向文件的address_space
			
		*/
		struct address_space *mapping;	/* If low bit clear, points to
						 * inode address_space, or NULL.
						 * If page mapped as anonymous
						 * memory, low bit is set, and
						 * it points to anon_vma object:
						 * see PAGE_MAPPING_ANON below.
						 */
		void *s_mem;			/* slab first object */
		atomic_t compound_mapcount;	/* first tail page */
		/* page_deferred_list().next	 -- second tail page */
	};


	/* Second double word */
	union 
	{
		/*
			作为不同含义的几种内核成分使用
			例如，在页磁盘映像或者匿名区中标识存放在页框中的数据的位置			      存放一个换出页标识符
			当此页作为映射页(文件映射)时，保存这块页的数据在整个文件数据中以页为大小的偏移量
            当此页作为匿名页时，保存此页在线性区vma内的页索引或者是页的线性地址/PAGE_SIZE。
            对于匿名页的page->index表示的是page在vma中的虚拟页框号(此页的开始线性地址 >> PAGE_SIZE)。共享匿名页的产生应该只有在fork，clone完成并写时复制之前。
		*/
		pgoff_t index;		/* Our offset within mapping. */
		/*
		用于SLAB和SLUB描述符，指向空闲对象链表
		*/
		void *freelist;		/* sl[aou]b first free object */
		/* page_deferred_list().prev	-- second tail page */
	};

	

	union {
#if defined(CONFIG_HAVE_CMPXCHG_DOUBLE) && \
	defined(CONFIG_HAVE_ALIGNED_STRUCT_PAGE)
		/* Used for cmpxchg_double in slub */
		unsigned long counters;
#else
		/*
		 * Keep _refcount separate from slub cmpxchg_double data.
		 * As the rest of the double word is protected by slab_lock
		 * but _refcount is not.
		 */
		unsigned counters;
#endif
		struct {

			union {
				/*
				 * Count of ptes mapped in mms, to show when
				 * page is mapped & limit reverse map searches.
				 *
				 * Extra information about page type may be
				 * stored here for pages that are never mapped,
				 * in which case the value MUST BE <= -2.
				 * See page-flags.h for more details.
				 */
				/*页框中页表项数目（如果没有则为-1）*/
				atomic_t _mapcount;

				unsigned int active;		/* SLAB */
				struct {			/* SLUB */
					unsigned inuse:16;
					unsigned objects:15;
					unsigned frozen:1;
				};
				int units;			/* SLOB */
			};
			/*
			 * Usage count, *USE WRAPPER FUNCTION* when manual
			 * accounting. See page_ref.h
			 */
			atomic_t _refcount;
		};
	};

	/*
	 * Third double word block
	 *
	 * WARNING: bit 0 of the first word encode PageTail(). That means
	 * the rest users of the storage space MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union 
	{
		/*
			包含页的最近最少使用（LRU）双向链表的指针
		*/
		struct list_head lru;	/* Pageout list, eg. active_list
					 * protected by zone_lru_lock !
					 * Can be used as a generic list
					 * by the page owner.
					 */
		struct dev_pagemap *pgmap; /* ZONE_DEVICE pages are never on an
					    * lru or handled by a slab
					    * allocator, this points to the
					    * hosting device page map.
					    */
		struct {		/* slub per cpu partial pages */
			struct page *next;	/* Next partial slab */
#ifdef CONFIG_64BIT
			int pages;	/* Nr of partial slabs left */
			int pobjects;	/* Approximate # of objects */
#else
			short int pages;
			short int pobjects;
#endif
		};

		struct rcu_head rcu_head;	/* Used by SLAB
						 * when destroying via RCU
						 */
		/* Tail pages of compound page */
		struct 
		{
			/* If bit zero is set 
				如果bit 0 被设置
			*/
			unsigned long compound_head; 

			/* First tail page only */
#ifdef CONFIG_64BIT
			/*
			 * On 64 bit system we have enough space in struct page
			 * to encode compound_dtor and compound_order with
			 * unsigned int. It can help compiler generate better or
			 * smaller code on some archtectures.
			 */
			unsigned int compound_dtor;
			unsigned int compound_order;
#else
			unsigned short int compound_dtor;
			unsigned short int compound_order;
#endif
		};



#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && USE_SPLIT_PMD_PTLOCKS
		struct {
			unsigned long __pad;	/* do not overlay pmd_huge_pte
						 * with compound_head to avoid
						 * possible bit 0 collision.
						 */
			pgtable_t pmd_huge_pte; /* protected by page->ptl */
		};
#endif
	};

	/* Remainder is not double word aligned */
	union 
	{
		/*
			可用于正在使用页的内核成分（例如，在缓冲页的情况下，它是一个缓冲器头指针）
			如果页是空闲的，则该字段由伙伴系统使用
		*/
		unsigned long private;		/* Mapping-private opaque data:
					 	 * usually used for buffer_heads
						 * if PagePrivate set; used for
						 * swp_entry_t if PageSwapCache;
						 * indicates order in the buddy
						 * system if PG_buddy is set.
						 */
#if USE_SPLIT_PTE_PTLOCKS
#if ALLOC_SPLIT_PTLOCKS
		spinlock_t *ptl;
#else
		spinlock_t ptl;
#endif
#endif
		struct kmem_cache *slab_cache;	/* SL[AU]B: Pointer to slab */
	};

#ifdef CONFIG_MEMCG
	struct mem_cgroup *mem_cgroup;
#endif

	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */

#ifdef CONFIG_KMEMCHECK
	/*
	 * kmemcheck wants to track the status of each byte in a page; this
	 * is a pointer to such a status block. NULL if not tracked.
	 */
	void *shadow;
#endif

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid;
#endif
}
/*
 * The struct page can be forced to be double word aligned so that atomic ops
 * on double words work. The SLUB allocator can make use of such a feature.
 */
#ifdef CONFIG_HAVE_ALIGNED_STRUCT_PAGE
	__aligned(2 * sizeof(unsigned long))
#endif
;

struct page_frag {
	struct page *page;
#if (BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)
	__u32 offset;
	__u32 size;
#else
	__u16 offset;
	__u16 size;
#endif
};

#define PAGE_FRAG_CACHE_MAX_SIZE	__ALIGN_MASK(32768, ~PAGE_MASK)
#define PAGE_FRAG_CACHE_MAX_ORDER	get_order(PAGE_FRAG_CACHE_MAX_SIZE)

struct page_frag_cache {
	void * va;
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	__u16 offset;
	__u16 size;
#else
	__u32 offset;
#endif
	/* we maintain a pagecount bias, so that we dont dirty cache line
	 * containing page->_refcount every time we allocate a fragment.
	 */
	unsigned int		pagecnt_bias;
	bool pfmemalloc;
};

typedef unsigned long vm_flags_t;

/*
 * A region containing a mapping of a non-memory backed file under NOMMU
 * conditions.  These are held in a global tree and are pinned by the VMAs that
 * map parts of them.
 */
struct vm_region {
	struct rb_node	vm_rb;		/* link in global region tree */
	vm_flags_t	vm_flags;	/* VMA vm_flags */
	unsigned long	vm_start;	/* start address of region */
	unsigned long	vm_end;		/* region initialised to here */
	unsigned long	vm_top;		/* region allocated to here */
	unsigned long	vm_pgoff;	/* the offset in vm_file corresponding to vm_start */
	struct file	*vm_file;	/* the backing file or NULL */

	int		vm_usage;	/* region usage count (access under nommu_region_sem) */
	bool		vm_icache_flushed : 1; /* true if the icache has been flushed for
						* this region */
};

#ifdef CONFIG_USERFAULTFD
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) { NULL, })
struct vm_userfaultfd_ctx {
	struct userfaultfd_ctx *ctx;
};
#else /* CONFIG_USERFAULTFD */
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) {})
struct vm_userfaultfd_ctx {};
#endif /* CONFIG_USERFAULTFD */

/*
 * This struct defines a memory VMM memory area. There is one of these
 * per VM-area/task.  A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
 /* 描述线性区结构 
 *     内核尽力把新分配的线性区与紧邻的现有线性区进程合并。
 * 如果两个相邻的线性区访问权限相匹配，就能把它们合并在一起。
 *     每个线性区都有一组连续号码的页(非页框)所组成，而页只有在被访问的时候系统会产生缺页异常，
   在异常中分配页框
 */
struct vm_area_struct 
{
	/* The first cache line has the info for VMA tree walking. */

	/*
		线性区内的第一个线性地址
	*/
	unsigned long vm_start;		/* Our start address within vm_mm. */
	/*
		线性区之外的第一个线性地址
	*/
	unsigned long vm_end;		/* The first byte after our end address within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	/*
		整个链表会按地址大小递增排序
		vm_next:线性区链表中的下一个线性区
		vm_prev：线性区链表中的上一个线性区
	*/
	struct vm_area_struct *vm_next, *vm_prev;

	/*
		用于组织当前内存描述符的线性区的红黑数的节点
	*/
	struct rb_node vm_rb;

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	/*
		此vma的子树中最大的空闲内存块的大小（bytes）	
	*/
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */

	/*
		指向所属的内存描述符
	*/
	struct mm_struct *vm_mm;	/* The address space we belong to. */
	/*
		页表项标志的初值，当增加一个页时，内核根据这个字段的值设置相应页表项中的标志
		页表中的User/SuperVisor标志应当总被置1
	*/
	pgprot_t vm_page_prot;		/* Access permissions of this VMA. */
	/*
		线性区标志
		读写可执行权限会复制当页表项中，由分页单元去检查这几个权限
	*/
	unsigned long vm_flags;		/* Flags, see mm.h. */

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap interval tree.
	 */

	/*
		连接到反向映射所用的数据结构，用于文件映射的线性区，主要用于文件页的反向映射
	*/
	struct 
	{
		struct rb_node rb;
		unsigned long rb_subtree_last;
	} shared;
	

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.

	 * 指向匿名线性区链表头的指针，这个链表会将此mm_struct中所有的匿名线性区连接起来
	 * 匿名的MAP_PIRVATE、堆和栈的vma都会存在于这个anon_vma_chain链表中
	 * 如果mm_struct的annon_vma为空，那么其anon_vma_chain也一定为空
	 */
	struct list_head anon_vma_chain; /* Serialized by mmap_sem &
					  * page_table_lock */
	/*指向anon_vma数据结构的指针，对于匿名线性区，此为重要结构
	*/		  
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	
	/* Function pointers to deal with this struct. */
	/*
		指向函数的指针，对于匿名线性区，此为重要结构
	*/
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: 
		如果此vma用于映射文件，那么保存的是在映射文件中的偏移量。
	如果是密名线性区，它等于0后者vma开始地址对应的虚拟页框号（vm_start >> PAGE_SIZE），
	这个虚拟页框号用于vma向下增长时反向映射的计算（栈）


	*/
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units */
	/*
		指向映射文件的文件对象，也可能指向建立shmem共享内存中返回的struct file，
	如果是匿名线性区，此值为NULL或者一个匿名文件
	*/
	struct file * vm_file;		/* File we map to (can be NULL). */

	/*
		指向内存区的私有数据
	*/
	void * vm_private_data;		/* was vm_pte (shared mem) */

#ifndef CONFIG_MMU
	struct vm_region *vm_region;	/* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

enum {
	MM_FILEPAGES,	/* Resident file mapping pages */
	MM_ANONPAGES,	/* Resident anonymous pages */
	MM_SWAPENTS,	/* Anonymous swap entries */
	MM_SHMEMPAGES,	/* Resident shared memory pages */
	NR_MM_COUNTERS
};

#if USE_SPLIT_PTE_PTLOCKS && defined(CONFIG_MMU)
#define SPLIT_RSS_COUNTING
/* per-thread cached information, */
struct task_rss_stat {
	int events;	/* for synchronization threshold */
	int count[NR_MM_COUNTERS];
};
#endif /* USE_SPLIT_PTE_PTLOCKS */

struct mm_rss_stat {
	atomic_long_t count[NR_MM_COUNTERS];
};

struct kioctx_table;


/* 
	内存描述符，每个进程都会有一个，除了内核线程(使用被调度出去的进程的mm_struct)和
	轻量级进程(使用父进程的mm_struct)

	所有的内存描述符存放在一个双向链表中，链表中第一个元素是init_mm，它是初始化阶段进程0的内存描述符
*/
struct mm_struct
{
	/*
		在地址空间中，mmap为地址空间的内存区域（用vm_area_struct结构来表示）链表，
		mm_rb用红黑树来存储，链表表示起来更加方便，红黑树表示起来更加方便查找。
		区别是，当虚拟区较少的时候，这个时候采用单链表，由mmap指向这个链表，当虚拟区多时此时采用红黑树的结构，
		由mm_rb指向这棵红黑树。这样就可以在大量数据的时候效率更高。
	*/
	/*
		指向线性区对象的链表头,链表是经过排序的，按线性地址升序排列，
		里面映射了匿名映射线性区和文件映射线性区
	*/
	
	struct vm_area_struct *mmap;		/* list of VMAs */
	/*
	* 指向线性区对象的红黑树的根
	*/
	struct rb_root mm_rb;
	u32 vmacache_seqnum;                   /* per-thread vmacache */
#ifdef CONFIG_MMU
	/*  在进程地址空间中找一个可以使用的线性地址空间，查找一个空闲的地址空间
	 *  len：指定区间的长度
	 *  返回新区间的起始地址
     */
	unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
#endif
	/* 标识第一个分配的匿名线性区或者文件内存映射的线性地址
     */
	unsigned long mmap_base;		/* base of mmap area */
	unsigned long mmap_legacy_base;         /* base of mmap area in bottom-up allocations */
	unsigned long task_size;		/* size of task vm space */
	/*
		所有vma中最大的结束地址
	*/
	unsigned long highest_vm_end;		/* highest vma end address */
	/*
	* 指向页全局目录
	*/
	pgd_t * pgd;
	/*
	* 次使用计数器，存放了共享此mm_struct的轻量级进程的个数，但所有的mm——users在mm——count的计算中只算作1
	*/
	atomic_t mm_users;			/* How many users with user space? */
	/*
		主使用计数器，当mm_count递减时，系统会检查是否为0，为0则解除这个mm_struct.
		初始为1
	*/
	atomic_t mm_count;			/* How many references to "struct mm_struct" (users count as 1) */
	/*
		页表数
	*/
	atomic_long_t nr_ptes;			/* PTE page table pages */
#if CONFIG_PGTABLE_LEVELS > 2
	atomic_long_t nr_pmds;			/* PMD page table pages */
#endif
	/*
		线性区的个数，默认最多是65535个，系统管理员可以通过写/proc/sys/vm/max_map_count文件修改这个值
	*/
	int map_count;				/* number of VMAs */

	/*
		线性区的自旋锁和页表的自旋锁
	*/
	spinlock_t page_table_lock;		/* Protects page tables and some counters */
	/*
		线性区的读写信号量，当需要对某个线性区进行操作时，会获取
	*/
	struct rw_semaphore mmap_sem;
	/*
		用于链入双向链表中
	*/
	struct list_head mmlist;		/* List of maybe swapped mm's.	These are globally strung
						 * together off init_mm.mmlist, and are protected
						 * by mmlist_lock
						 */

	/*
	进程所拥有的最大页框数
	*/
	unsigned long hiwater_rss;	/* High-watermark of RSS usage */
	/*
		进程线性区中的最大页数
	*/
	unsigned long hiwater_vm;	/* High-water virtual memory usage */
	/*
	进程地址空间的大小（页框数）
	*/
	unsigned long total_vm;		/* Total pages mapped */
	/*锁住而不能换出的页的数量
	*/
	unsigned long locked_vm;	/* Pages that have PG_mlocked set */
	unsigned long pinned_vm;	/* Refcount permanently increased */
	unsigned long data_vm;		/* VM_WRITE & ~VM_SHARED & ~VM_STACK */
	/*
	可执行内存映射中的页数量
	*/
	unsigned long exec_vm;		/* VM_EXEC & ~VM_WRITE & ~VM_STACK */
	/*
		用户态栈的页数量
	*/
	unsigned long stack_vm;		/* VM_STACK */
	unsigned long def_flags;
	/*
		start_code: 可执行代码的起始位置
		end_code:可执行代码的最后位置
		start_data:已经初始化数据的起始位置
		end_data:已经初始化数据的最后位置
	*/
	unsigned long start_code, end_code, start_data, end_data;
	/*
		start_brk:堆的起始位置
		brk:堆的当前最后地址
		start_stack:用户态栈的起始地址
	*/
	unsigned long start_brk, brk, start_stack;
	/*
		arg_start:命令行参数的起始位置
		arg_end:  命令行参数的最后位置
		env_start: 环境变量的起始位置
		env_end;   环境变量的最后位置
	*/
	unsigned long arg_start, arg_end, env_start, env_end;

	unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

	/*
	 * Special counters, in some configurations protected by the
	 * page_table_lock, in other configurations by being atomic.
	 */
	struct mm_rss_stat rss_stat;

	struct linux_binfmt *binfmt;

	cpumask_var_t cpu_vm_mask_var;

	/* Architecture-specific MM context */
	mm_context_t context;

	unsigned long flags; /* Must use atomic bitops to access the bits */

	struct core_state *core_state; /* coredumping support */
#ifdef CONFIG_AIO
	spinlock_t			ioctx_lock;
	struct kioctx_table __rcu	*ioctx_table;
#endif
#ifdef CONFIG_MEMCG
	/*
	 * "owner" points to a task that is regarded as the canonical
	 * user/owner of this mm. All of the following must be true in
	 * order for it to be changed:
	 *
	 * current == mm->owner
	 * current->mm != mm
	 * new_owner->mm == mm
	 * new_owner->alloc_lock is held

	 * 所属进程
	 */
	struct task_struct __rcu *owner;
#endif
	struct user_namespace *user_ns;

	/* store ref to file /proc/<pid>/exe symlink points to 
		代码段中映射的可执行文件的file
	*/
	struct file __rcu *exe_file;
#ifdef CONFIG_MMU_NOTIFIER
	struct mmu_notifier_mm *mmu_notifier_mm;
#endif
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
	pgtable_t pmd_huge_pte; /* protected by page_table_lock */
#endif
#ifdef CONFIG_CPUMASK_OFFSTACK
	struct cpumask cpumask_allocation;
#endif
#ifdef CONFIG_NUMA_BALANCING
	/*
	 * numa_next_scan is the next time that the PTEs will be marked
	 * pte_numa. NUMA hinting faults will gather statistics and migrate
	 * pages to new nodes if necessary.
	 */
	unsigned long numa_next_scan;

	/* Restart point for scanning and setting pte_numa */
	unsigned long numa_scan_offset;

	/* numa_scan_seq prevents two threads setting pte_numa */
	int numa_scan_seq;
#endif
#if defined(CONFIG_NUMA_BALANCING) || defined(CONFIG_COMPACTION)
	/*
	 * An operation with batched TLB flushing is going on. Anything that
	 * can move process memory needs to flush the TLB when moving a
	 * PROT_NONE or PROT_NUMA mapped page.
	 */
	bool tlb_flush_pending;
#endif
	struct uprobes_state uprobes_state;
#ifdef CONFIG_HUGETLB_PAGE
	atomic_long_t hugetlb_usage;
#endif
	struct work_struct async_put_work;
};

static inline void mm_init_cpumask(struct mm_struct *mm)
{
#ifdef CONFIG_CPUMASK_OFFSTACK
	mm->cpu_vm_mask_var = &mm->cpumask_allocation;
#endif
	cpumask_clear(mm->cpu_vm_mask_var);
}

/* Future-safe accessor for struct mm_struct's cpu_vm_mask. */
static inline cpumask_t *mm_cpumask(struct mm_struct *mm)
{
	return mm->cpu_vm_mask_var;
}

#if defined(CONFIG_NUMA_BALANCING) || defined(CONFIG_COMPACTION)
/*
 * Memory barriers to keep this state in sync are graciously provided by
 * the page table locks, outside of which no page table modifications happen.
 * The barriers below prevent the compiler from re-ordering the instructions
 * around the memory barriers that are already present in the code.
 */
static inline bool mm_tlb_flush_pending(struct mm_struct *mm)
{
	barrier();
	return mm->tlb_flush_pending;
}
static inline void set_tlb_flush_pending(struct mm_struct *mm)
{
	mm->tlb_flush_pending = true;

	/*
	 * Guarantee that the tlb_flush_pending store does not leak into the
	 * critical section updating the page tables
	 */
	smp_mb__before_spinlock();
}
/* Clearing is done after a TLB flush, which also provides a barrier. */
static inline void clear_tlb_flush_pending(struct mm_struct *mm)
{
	barrier();
	mm->tlb_flush_pending = false;
}
#else
static inline bool mm_tlb_flush_pending(struct mm_struct *mm)
{
	return false;
}
static inline void set_tlb_flush_pending(struct mm_struct *mm)
{
}
static inline void clear_tlb_flush_pending(struct mm_struct *mm)
{
}
#endif

struct vm_fault;

struct vm_special_mapping {
	const char *name;	/* The name, e.g. "[vdso]". */

	/*
	 * If .fault is not provided, this points to a
	 * NULL-terminated array of pages that back the special mapping.
	 *
	 * This must not be NULL unless .fault is provided.
	 */
	struct page **pages;

	/*
	 * If non-NULL, then this is called to resolve page faults
	 * on the special mapping.  If used, .pages is not checked.
	 */
	int (*fault)(const struct vm_special_mapping *sm,
		     struct vm_area_struct *vma,
		     struct vm_fault *vmf);

	int (*mremap)(const struct vm_special_mapping *sm,
		     struct vm_area_struct *new_vma);
};

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH,
	TLB_REMOTE_SHOOTDOWN,
	TLB_LOCAL_SHOOTDOWN,
	TLB_LOCAL_MM_SHOOTDOWN,
	TLB_REMOTE_SEND_IPI,
	NR_TLB_FLUSH_REASONS,
};

 /*
  * A swap entry has to fit into a "unsigned long", as the entry is hidden
  * in the "index" field of the swapper address space.
  */
typedef struct {
	unsigned long val;
} swp_entry_t;

#endif /* _LINUX_MM_TYPES_H */

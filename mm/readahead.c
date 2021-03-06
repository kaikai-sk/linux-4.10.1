/*
 * mm/readahead.c - address_space-level file readahead.
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 09Apr2002	Andrew Morton
 *		Initial version.
 */

#include <linux/kernel.h>
#include <linux/dax.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/pagevec.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/mm_inline.h>

#include "internal.h"

/*
 * Initialise a struct file's readahead state.  Assumes that the caller has
 * memset *ra to zero.
 */
void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping)
{
	ra->ra_pages = inode_to_bdi(mapping->host)->ra_pages;
	ra->prev_pos = -1;
}
EXPORT_SYMBOL_GPL(file_ra_state_init);

/*
 * see if a page needs releasing upon read_cache_pages() failure
 * - the caller of read_cache_pages() may have set PG_private or PG_fscache
 *   before calling, such as the NFS fs marking pages that are cached locally
 *   on disk, thus we need to give the fs a chance to clean up in the event of
 *   an error
 */
static void read_cache_pages_invalidate_page(struct address_space *mapping,
					     struct page *page)
{
	if (page_has_private(page)) {
		if (!trylock_page(page))
			BUG();
		page->mapping = mapping;
		do_invalidatepage(page, 0, PAGE_SIZE);
		page->mapping = NULL;
		unlock_page(page);
	}
	put_page(page);
}

/*
 * release a list of pages, invalidating them first if need be
 */
static void read_cache_pages_invalidate_pages(struct address_space *mapping,
					      struct list_head *pages)
{
	struct page *victim;

	while (!list_empty(pages)) {
		victim = lru_to_page(pages);
		list_del(&victim->lru);
		read_cache_pages_invalidate_page(mapping, victim);
	}
}

/**
 * read_cache_pages - populate an address space with some pages & start reads against them
 * @mapping: the address_space
 * @pages: The address of a list_head which contains the target pages.  These
 *   pages have their ->index populated and are otherwise uninitialised.
 * @filler: callback routine for filling a single page.
 * @data: private data for the callback routine.
 *
 * Hides the details of the LRU cache etc from the filesystems.
 */
int read_cache_pages(struct address_space *mapping, struct list_head *pages,
			int (*filler)(void *, struct page *), void *data)
{
	struct page *page;
	int ret = 0;

	while (!list_empty(pages)) {
		page = lru_to_page(pages);
		list_del(&page->lru);
		if (add_to_page_cache_lru(page, mapping, page->index,
				readahead_gfp_mask(mapping))) {
			read_cache_pages_invalidate_page(mapping, page);
			continue;
		}
		put_page(page);

		ret = filler(data, page);
		if (unlikely(ret)) {
			read_cache_pages_invalidate_pages(mapping, pages);
			break;
		}
		task_io_account_read(PAGE_SIZE);
	}
	return ret;
}

EXPORT_SYMBOL(read_cache_pages);

// 
//
//
//
//
//
//
//
static int read_pages(struct address_space *mapping, struct file *filp,
		struct list_head *pages, unsigned int nr_pages, gfp_t gfp)
{
	struct blk_plug plug;
	unsigned page_idx;
	int ret;

	blk_start_plug(&plug);

	//如果	存在readpages指针，使用readpages读取数据
	if (mapping->a_ops->readpages) 
	{
		//读取一段数据
		ret = mapping->a_ops->readpages(filp, mapping, pages, nr_pages);
		/* Clean up the remaining pages 
			清理页
		*/
		put_pages_list(pages);
		goto out;
	}

	/*
		对于某些不存在readpages接口的设备，使用readpage函数循环读取
	*/
	for (page_idx = 0; page_idx < nr_pages; page_idx++) 
	{
		//获取page指针
		struct page *page = lru_to_page(pages);
		//将这个page从page pool中删除
		list_del(&page->lru);
		if (!add_to_page_cache_lru(page, mapping, page->index, gfp)) //将该页面加入page cache
		{
			//调用回调函数，将该页从磁盘上读取出来
			mapping->a_ops->readpage(filp, page);
		}
		//page_cache_realease(page)清理页
		put_page(page);
	}
	ret = 0;

out:
	blk_finish_plug(&plug);

	return ret;
}

/*
 * __do_page_cache_readahead() actually reads a chunk of disk.  It allocates all
 * the pages first, then submits them all for I/O. This avoids the very bad
 * behaviour which would occur if page allocations are causing VM writeback.
 * We really don't want to intermingle reads and writes like that.
 * 
 * __do_page_cache_readahead（）实际上读取一块磁盘。 
 * 它首先分配所有页面，然后将它们全部提交给I / O。 
 * 这可以避免页面分配导致虚拟机回写时发生的非常不好的行为。 我们真的不想像这样混淆读写。
 *
 * mapping：文件拥有者的addresss_space对象
 * filp：文件对象
 * offset：页面在文件内的偏移量
 * nr_to_read：完成当前读操作需要的页面数
 * lookahead_size：异步预读大小
 * 
 * Returns the number of pages requested, or the maximum amount of I/O allowed.
 * 返回请求的页数或者是最大的被允许的IO数
 */
int __do_page_cache_readahead(struct address_space *mapping, struct file *filp,
			pgoff_t offset, unsigned long nr_to_read,
			unsigned long lookahead_size)
{
	struct inode *inode = mapping->host;
	struct page *page;
	unsigned long end_index;	/* The last page we want to read */
	LIST_HEAD(page_pool);
	int page_idx;
	int ret = 0;
	//获得文件大小
	loff_t isize = i_size_read(inode);
	gfp_t gfp_mask = readahead_gfp_mask(mapping);

	//如果文件大小等于0，直接返回
	if (isize == 0)
		goto out;

	//计算文件的长度，以页为单位，并且要加1
	end_index = ((isize - 1) >> PAGE_SHIFT);

	/*
	 * Preallocate as many pages as we will need.
	 * 这个for循环的功能：在从磁盘上读取数据之前，首先预分配一些内存页面，
	 * 用来存放读取的文件数据
	 */
	for (page_idx = 0; page_idx < nr_to_read; page_idx++)
	{
		pgoff_t page_offset = offset + page_idx;

		//判断是否到了文件的尾部
		if (page_offset > end_index)
			break;

		//这三行代码的功能：
		//在预读过程中，可能有其他进程已经将某些页面读进内存，
		//因此在此检查页面是否已经在cache中
		//使用Ready-Copy Update锁
		rcu_read_lock();
		//搜索页缓存的基树，看要预取的页是否已经在page cache中了
		page = radix_tree_lookup(&mapping->page_tree, page_offset);
		//释放锁
		rcu_read_unlock();
		
		if (page && !radix_tree_exceptional_entry(page))
			continue;

		//若page cache中没有所请求的页面，则分配页面
		page = __page_cache_alloc(gfp_mask);
		if (!page)
			break;

//		初始化该页面
		page->index = page_offset;
		//并将页面加入到页面池中
		list_add(&page->lru, &page_pool);
		//当分配到nr_to_read - lookahead_size个页面时，就
		//设置该页面标志PG_readahead,已让下次进行异步预读
		if (page_idx == nr_to_read - lookahead_size)
			SetPageReadahead(page);
		ret++;
	}

	/*
	 * Now start the IO.  We ignore I/O errors - if the page is not
	 * uptodate then the caller will launch readpage again, and
	 * will then handle the error.
	 *
	 * 当页面准备好之后，调用read_pages()执行IO操作，从磁盘读取文件数据
	 */
	if (ret)
		read_pages(mapping, filp, &page_pool, ret, gfp_mask);
	BUG_ON(!list_empty(&page_pool));
out:
	return ret;
}

/*
 * Chunk the readahead into 2 megabyte units, so that we don't pin too much
 * memory at once.
 */
int force_page_cache_readahead(struct address_space *mapping, struct file *filp,
			       pgoff_t offset, unsigned long nr_to_read)
{
	struct backing_dev_info *bdi = inode_to_bdi(mapping->host);
	struct file_ra_state *ra = &filp->f_ra;
	unsigned long max_pages;

	if (unlikely(!mapping->a_ops->readpage && !mapping->a_ops->readpages))
		return -EINVAL;

	/*
	 * If the request exceeds the readahead window, allow the read to
	 * be up to the optimal hardware IO size
	 */
	max_pages = max_t(unsigned long, bdi->io_pages, ra->ra_pages);
	nr_to_read = min(nr_to_read, max_pages);
	while (nr_to_read) {
		int err;

		unsigned long this_chunk = (2 * 1024 * 1024) / PAGE_SIZE;

		if (this_chunk > nr_to_read)
			this_chunk = nr_to_read;
		err = __do_page_cache_readahead(mapping, filp,
						offset, this_chunk, 0);
		if (err < 0)
			return err;

		offset += this_chunk;
		nr_to_read -= this_chunk;
	}
	return 0;
}

/*
 * Set the initial window size, round to next power of 2 and square
 * for small size, x 4 for medium, and x 2 for large
 * for 128k (32 page) max ra
 * 1-8 page = 32k initial, > 8 page = 128k initial
 *
 * size: 请求的页面数量
 * max:  预读窗口的最大页面数量
 */
static unsigned long get_init_ra_size(unsigned long size, unsigned long max)
{
	//计算出跟size大小最接近的2^
	unsigned long newsize = roundup_pow_of_two(size);

	if (newsize <= max / 32)
	{
		newsize = newsize * 4;
	}
	else if (newsize <= max / 4)
		newsize = newsize * 2;
	else
		newsize = max;

	return newsize;
}

/*
 *  Get the previous window size, ramp it up, and
 *  return it as the new window size.
 */
static unsigned long get_next_ra_size(struct file_ra_state *ra,
						unsigned long max)
{
	//当前窗口大小
	unsigned long cur = ra->size;
	unsigned long newsize;

	if (cur < max / 16)
		newsize = 4 * cur;
	else
	{
		newsize = 2 * cur;
	}

	return min(newsize, max);
}

/*
 * On-demand readahead design.
 *
 * The fields in struct file_ra_state represent the most-recently-executed
 * readahead attempt:
 *
 *                        |<----- async_size ---------|
 *     |------------------- size -------------------->|
 *     |==================#===========================|
 *     ^start             ^page marked with PG_readahead
 *
 * To overlap application thinking time and disk I/O time, we do
 * `readahead pipelining': Do not wait until the application consumed all
 * readahead pages and stalled on the missing page at readahead_index;
 * Instead, submit an asynchronous readahead I/O as soon as there are
 * only async_size pages left in the readahead window. Normally async_size
 * will be equal to size, for maximum pipelining.
 *
 * In interleaved sequential reads, concurrent streams on the same fd can
 * be invalidating each other's readahead state. So we flag the new readahead
 * page at (start+size-async_size) with PG_readahead, and use it as readahead
 * indicator. The flag won't be set on already cached pages, to avoid the
 * readahead-for-nothing fuss, saving pointless page cache lookups.
 *
 * prev_pos tracks the last visited byte in the _previous_ read request.
 * It should be maintained by the caller, and will be used for detecting
 * small random reads. Note that the readahead algorithm checks loosely
 * for sequential patterns. Hence interleaved reads might be served as
 * sequential ones.
 *
 * There is a special-case: if the first page which the application tries to
 * read happens to be the first page of the file, it is assumed that a linear
 * read is about to happen and the window is immediately set to the initial size
 * based on I/O request size and the max_readahead.
 *
 * The code ramps up the readahead size aggressively at first, but slow down as
 * it approaches max_readhead.
 */

/*
 * Count contiguously cached pages from @offset-1 to @offset-@max,
 * this count is a conservative estimation of
 * 	- length of the sequential read sequence, or
 * 	- thrashing threshold in memory tight systems
 */
static pgoff_t count_history_pages(struct address_space *mapping,
				   pgoff_t offset, unsigned long max)
{
	pgoff_t head;

	rcu_read_lock();
	head = page_cache_prev_hole(mapping, offset - 1, max);
	rcu_read_unlock();

	return offset - 1 - head;
}

/*
 * page cache context based read-ahead
 */
static int try_context_readahead(struct address_space *mapping,
				 struct file_ra_state *ra,
				 pgoff_t offset,
				 unsigned long req_size,
				 unsigned long max)
{
	pgoff_t size;

	size = count_history_pages(mapping, offset, max);

	/*
	 * not enough history pages:
	 * it could be a random read
	 */
	if (size <= req_size)
		return 0;

	/*
	 * starts from beginning of file:
	 * it is a strong indication of long-run stream (or whole-file-read)
	 */
	if (size >= offset)
		size *= 2;

	ra->start = offset;
	ra->size = min(size + req_size, max);
	ra->async_size = 1;

	return 1;
}

/*
 * A minimal readahead algorithm for trivial sequential/random reads.
 * 该函数主要根据file_ra_state描述符中的成员变量来执行一些动作 

 * （1）首先判断如果是从文件头开始读取的，初始化预读信息。默认设置预读为4个page。
 * （2）如果不是文件头，则判断是否连续的读取请求，如果是则扩大预读数量。一般等
 *      于上次预读数量x2。
 * （3）否则就是随机的读取，不适用预读，只读取sys_read请求的数量
 * （4）然后调用ra_submit提交读取请求。
 */
 
static unsigned long
ondemand_readahead(struct address_space *mapping,
		   struct file_ra_state *ra, struct file *filp,
		   bool hit_readahead_marker, pgoff_t offset,
		   unsigned long req_size)
{
	struct backing_dev_info *bdi = inode_to_bdi(mapping->host);
	//最大的预取窗口
	unsigned long max_pages = ra->ra_pages;
	pgoff_t prev_offset;

	/*
	 * If the request exceeds the readahead window, allow the read to
	 * be up to the optimal hardware IO size
	 */
	if (req_size > max_pages && bdi->io_pages > max_pages)
		max_pages = min(req_size, bdi->io_pages);

	/*
	 * start of file
	 * 如果是从文件头开始读取的，初始化预读信息
	 * 默认设置预读为4个page
	 */
	if (!offset)
		goto initial_readahead;


	/*
	 * It's the expected callback offset, assume sequential access.
	 * Ramp up sizes, and push forward the readahead window.

	 * 这是预期的回调分支,假设顺序访问。
	 * 加大尺寸，并推进预读窗口
	 */
	/*
		 如果:
     * 1. 顺序读(本次读偏移为上次读偏移(ra->start) + 读大小(ra->size,包含预读量) - 
     *  上次预读大小(ra->async_size))
     * 2. offset == (ra->start + ra->size)???
	*/
	if ((offset == (ra->start + ra->size - ra->async_size) ||
	     offset == (ra->start + ra->size))) //判定为顺序读
	{
		ra->start += ra->size;
		ra->size = get_next_ra_size(ra, max_pages);
		ra->async_size = ra->size;
		goto readit;
	}

	/*
	 * Hit a marked page without valid readahead state.
	 * E.g. interleaved reads.
	 * Query the pagecache for async_size, which normally equals to
	 * readahead size. Ramp it up and use it as the new readahead size.
	 * 
	 * 在没有合法的readahead状态的时候命中一个标记的页面
	 * 例如，交织读
	 * 查询async_size的pagecache，async_size通常等于readadhead的大小。
	 * 将其升级并将用作新的预读大小
	 */
	if (hit_readahead_marker) 
	{
		pgoff_t start;

		rcu_read_lock();
		start = page_cache_next_hole(mapping, offset + 1, max_pages);
		rcu_read_unlock();

		if (!start || start - offset > max_pages)
			return 0;

		ra->start = start;
		ra->size = start - offset;	/* old async_size */
		ra->size += req_size;
		ra->size = get_next_ra_size(ra, max_pages);
		ra->async_size = ra->size;
		goto readit;
	}

	/*
	 * oversize read
	 * 超大的读
	 */
	if (req_size > max_pages)
		goto initial_readahead;

	/*
	 * sequential cache miss
	 * trivial case: (offset - prev_offset) == 1
	 * unaligned reads: (offset - prev_offset) == 0

	 * 顺序缓存未命中
	 * 微不足道的情况 (offset - prev_offset) == 1
	 * 未对齐的读取：(offset - prev_offset) == 0
	 */
	prev_offset = (unsigned long long)ra->prev_pos >> PAGE_SHIFT;
	if (offset - prev_offset <= 1UL)
		goto initial_readahead;

	/*
	 * Query the page cache and look for the traces(cached history pages)
	 * that a sequential stream would leave behind.

	 * 查询page cache并且查找顺序流可能会留下的trace（缓存的历史记录页面）
	 */
	if (try_context_readahead(mapping, ra, offset, req_size, max_pages))
		goto readit;

	/*
	 * standalone, small random read
	 * 独立 小的随机的读
	 * Read as is, and do not pollute the readahead state.
	 * 按原样读，不要污染预读的状态
	 */
	return __do_page_cache_readahead(mapping, filp, offset, req_size, 0);

initial_readahead:
	ra->start = offset;
	//get_init_ra_size()计算初始预读窗口大小
	ra->size = get_init_ra_size(req_size, max_pages);
	ra->async_size = ra->size > req_size ? ra->size - req_size : ra->size;

readit:
	/*
	 * Will this read hit the readahead marker made by itself?
	 * If so, trigger the readahead marker hit now, and merge
	 * the resulted next readahead window into the current one.
	 *
	 * 这次读会不会命中自己制作的预读标记？？
	 * 如果是这样的话，立即触发预读标记命中。
	 * 并将结果的下一个窗口合并到当前预读窗口中
	 */
	if (offset == ra->start && ra->size == ra->async_size) 
	{
		//get_next_ra_size() 计算下一个预读窗口大小。
		ra->async_size = get_next_ra_size(ra, max_pages);
		ra->size += ra->async_size;
	}

	return ra_submit(ra, mapping, filp);
}

/**
 * page_cache_sync_readahead - generic file readahead
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @filp: passed on to ->readpage() and ->readpages()
 * @offset: start offset into @mapping, in pagecache page-sized units
 * @req_size: hint: total size of the read which the caller is performing in
 *            pagecache pages
 *
 * page_cache_sync_readahead() should be called when a cache miss happened:
 * it will submit the read.  The readahead logic may decide to piggyback more
 * pages onto the read request if access patterns suggest it will improve
 * performance.
 * 重新装满当前窗口和前进窗口（ahead window），并根据预读命中率来更新窗口大小
 * 参数：
 * mapping:文件拥有着的address_space对象
 * ra：包含此页面的file_ra_state描述符
 * filp:文件对象
 * offset:页面在文件内的偏移量
 * req_size:完成当前读操作所需要的页面数
 */
void page_cache_sync_readahead(struct address_space *mapping,
			       struct file_ra_state *ra, struct file *filp,
			       pgoff_t offset, unsigned long req_size)
{
	/* no read-ahead */
	if (!ra->ra_pages)
		return;

	/* be dumb 闷声不响（无语了） */
	//当文件模式设置FMODE_RANDOM时，表示文件预期为随机访问。这种情形比较少见.
	if (filp && (filp->f_mode & FMODE_RANDOM)) {
		force_page_cache_readahead(mapping, filp, offset, req_size);
		return;
	}

	/* do read-ahead */
	//函数变成对ondemand_readahead（）封装。
	ondemand_readahead(mapping, ra, filp, false, offset, req_size);
}
EXPORT_SYMBOL_GPL(page_cache_sync_readahead);

/**
 * page_cache_async_readahead - file readahead for marked pages
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @filp: passed on to ->readpage() and ->readpages()
 * @page: the page at @offset which has the PG_readahead flag set
 * @offset: start offset into @mapping, in pagecache page-sized units
 * @req_size: hint: total size of the read which the caller is performing in
 *            pagecache pages
 *
 * page_cache_async_readahead() should be called when a page is used which
 * has the PG_readahead flag; this is a marker to suggest that the application
 * has used up enough of the readahead window that we should start pulling in
 * more pages.
 */
void
page_cache_async_readahead(struct address_space *mapping,
			   struct file_ra_state *ra, struct file *filp,
			   struct page *page, pgoff_t offset,
			   unsigned long req_size)
{
	/* no read-ahead */
	//如果不需要预读，直接返回
	if (!ra->ra_pages)
		return;

	/*
	 * Same bit is used for PG_readahead and PG_reclaim.
	 * 如果页面处于写回状态，直接返回
	 */
	if (PageWriteback(page))
		return;

	//通过了前面的检查之后，就清楚页面的PG_head标志
	ClearPageReadahead(page);

	/*
	 * Defer asynchronous read-ahead on IO congestion.
	 * 在执行预读前，还要检查磁盘IO是否处于拥塞状态，
	 * 若处于拥塞状态，就不能再进行预读
	 */
	if (inode_read_congested(mapping->host))
		return;

	/* do read-ahead 
	   接下来就调用ondemand_readahead()执行真正的预读
	*/
	ondemand_readahead(mapping, ra, filp, true, offset, req_size);
}
EXPORT_SYMBOL_GPL(page_cache_async_readahead);

static ssize_t
do_readahead(struct address_space *mapping, struct file *filp,
	     pgoff_t index, unsigned long nr)
{
	if (!mapping || !mapping->a_ops)
		return -EINVAL;

	/*
	 * Readahead doesn't make sense for DAX inodes, but we don't want it
	 * to report a failure either.  Instead, we just return success and
	 * don't do any work.
	 */
	if (dax_mapping(mapping))
		return 0;

	return force_page_cache_readahead(mapping, filp, index, nr);
}

SYSCALL_DEFINE3(readahead, int, fd, loff_t, offset, size_t, count)
{
	ssize_t ret;
	struct fd f;

	ret = -EBADF;
	f = fdget(fd);
	if (f.file) {
		if (f.file->f_mode & FMODE_READ) {
			struct address_space *mapping = f.file->f_mapping;
			pgoff_t start = offset >> PAGE_SHIFT;
			pgoff_t end = (offset + count - 1) >> PAGE_SHIFT;
			unsigned long len = end - start + 1;
			ret = do_readahead(mapping, f.file, start, len);
		}
		fdput(f);
	}
	return ret;
}

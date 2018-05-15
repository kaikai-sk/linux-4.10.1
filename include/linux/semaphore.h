/*
 * Copyright (c) 2008 Intel Corporation
 * Author: Matthew Wilcox <willy@linux.intel.com>
 *
 * Distributed under the terms of the GNU GPL, version 2
 *
 * Please see kernel/semaphore.c for documentation of these functions
 */
#ifndef __LINUX_SEMAPHORE_H
#define __LINUX_SEMAPHORE_H

#include <linux/list.h>
#include <linux/spinlock.h>

/* 
	Please don't access any members of this structure directly 

	信号量
*/
struct semaphore 
{
	//用于对数据结构中的count和wait_list成员进行保护
	raw_spinlock_t		lock;
	//允许进入临界区的内核执行路径的个数	
	unsigned int		count;
	//管理所有在信号量上面睡眠的进程，没有成功获取锁的进程会睡眠在这个链表上	
	struct list_head	wait_list;
};


#define __SEMAPHORE_INITIALIZER(name, n)				\
{									\
	.lock		= __RAW_SPIN_LOCK_UNLOCKED((name).lock),	\
	.count		= n,						\
	.wait_list	= LIST_HEAD_INIT((name).wait_list),		\
}

#define DEFINE_SEMAPHORE(name)	\
	struct semaphore name = __SEMAPHORE_INITIALIZER(name, 1)

/*
	信号初始化
*/
static inline void sema_init(struct semaphore *sem, int val)
{
	static struct lock_class_key __key;
	/*
		__SEMAPHORE_INITIALIZER（）会完成对信号量数据结构的填充，
		val值通常设定为1
	*/	
	*sem = (struct semaphore) __SEMAPHORE_INITIALIZER(*sem, val);
	lockdep_init_map(&sem->lock.dep_map, "semaphore->lock", &__key, 0);
}

extern void down(struct semaphore *sem);
extern int __must_check down_interruptible(struct semaphore *sem);
extern int __must_check down_killable(struct semaphore *sem);
extern int __must_check down_trylock(struct semaphore *sem);
extern int __must_check down_timeout(struct semaphore *sem, long jiffies);
extern void up(struct semaphore *sem);

#endif /* __LINUX_SEMAPHORE_H */

#ifndef _ASM_GENERIC_BITOPS_LOCK_H_
#define _ASM_GENERIC_BITOPS_LOCK_H_

/**
 * test_and_set_bit_lock - Set a bit and return its old value, for lock
 *                         设置一个bit并且返回它的旧值，为了锁
 * @nr: Bit to set                要设置的比特
 * @addr: Address to count from   要计数的地址
 *
 * This operation is atomic and provides acquire barrier semantics.
 * It can be used to implement bit locks.
 * 这个操作是原子操作，并提供获取屏障语义。它可以用来实现位锁。
 */
#define test_and_set_bit_lock(nr, addr)	test_and_set_bit(nr, addr)

/**
 * clear_bit_unlock - Clear a bit in memory, for unlock
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * This operation is atomic and provides release barrier semantics.
 */
#define clear_bit_unlock(nr, addr)	\
do {					\
	smp_mb__before_atomic();	\
	clear_bit(nr, addr);		\
} while (0)

/**
 * __clear_bit_unlock - Clear a bit in memory, for unlock
 * @nr: the bit to set
 * @addr: the address to start counting from
 *
 * A weaker form of clear_bit_unlock() as used by __bit_lock_unlock(). If all
 * the bits in the word are protected by this lock some archs can use weaker
 * ops to safely unlock.
 *
 * See for example x86's implementation.
 */
#define __clear_bit_unlock(nr, addr)	\
do {					\
	smp_mb__before_atomic();	\
	clear_bit(nr, addr);		\
} while (0)

#endif /* _ASM_GENERIC_BITOPS_LOCK_H_ */


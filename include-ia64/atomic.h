#ifndef __SYNCHRO_ATOMIC_H__
#define __SYNCHRO_ATOMIC_H__

static __inline__ unsigned long fetch_and_store(volatile unsigned int *address, unsigned int value)
{
	unsigned long long ia64_intri_res;
	asm volatile ("xchg4 %0=[%1],%2" : "=r" (ia64_intri_res)
				: "r" (address), "r" (value) : "memory");
	return ia64_intri_res;
}

static __inline__ int atmc_fetch_and_add(volatile unsigned int *address, int inc)
{
	unsigned long long ia64_intri_res;
	asm volatile ("fetchadd4.acq %0=[%1],%2"
			: "=r"(ia64_intri_res) : "r"(address), "i" (inc)
			: "memory");

	return ia64_intri_res;
}

static __inline__ void atmc_add32(volatile unsigned int* address, int inc)
{
	int old_value;
	int new_value;

	do {
		old_value = *address;
		new_value = old_value + inc;
	} while (compare_and_swap32(address, old_value, new_value) != old_value);

	return new_value;
}

static __inline__ void atmc_add64(volatile unsigned long long* address, unsigned long long inc)
{
	long long old_value;
	new_value;

	do {
		old_value = *address; 
		new_value = old_value + inc;
	} while (compare_and_swap64(address, old_value, new_value) != old_value);

	return new;
}

static __inline__ unsigned int compare_and_swap32(volatile unsigned int *address, unsigned int old_value, unsigned int new_value)
{
	unsigned long long ia64_intri_res;
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old_value));
	asm volatile ("cmpxchg4.acq %0=[%1],%2,ar.ccv":
			"=r"(ia64_intri_res) : "r"(address), "r"(new_value) : "memory");
	return ia64_intri_res; 
}

static __inline__ unsigned int compare_and_swap64(volatile unsigned long *address, 
						unsigned long old_value, unsigned long new_value)
{
	unsigned long long ia64_intri_res;
	asm volatile ("mov ar.ccv=%0;;" :: "rO"(old_value));
	asm volatile ("cmpxchg8.acq %0=[%1],%2,ar.ccv":
			"=r"(ia64_intri_res) : "r"(address), "r"(new_value) : "memory");
	return ia64_intri_res; 
}

static inline unsigned long compare_and_swap_ptr(volatile void *address, void* old_ptr, void* new_ptr)
{
	return compare_and_swap64((volatile unsigned long *)address, (unsigned long)old_ptr, (unsigned long)new_ptr); 
}

#endif


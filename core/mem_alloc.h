/* a tiny shim layer to switch between rte_malloc and malloc 
 * (or something else in the future) */

#ifndef _MEM_ALLOC_H_
#define _MEM_ALLOC_H_

#include <stddef.h>

#define LIBC			0
#define DPDK			1

/* either LIBC or DPDK */
#define MEM_ALLOC_PROVIDER	DPDK

#if MEM_ALLOC_PROVIDER == LIBC

#include <stdlib.h>
#include <string.h>

/* zero initialized by default */
static void *mem_alloc(size_t size)
{
	void *ptr = malloc(size);

	if (ptr)
		memset(ptr, 0, size);

	return ptr;
}

static void *mem_realloc(void *ptr, size_t size)
{
	return realloc(ptr, size);
}

static void mem_free(void *ptr)
{
	free(ptr);
}

#elif MEM_ALLOC_PROVIDER == DPDK

#include <rte_config.h>
#include <rte_malloc.h>

static void *mem_alloc(size_t size)
{
	return rte_zmalloc(/* name= */ NULL, size, /* align= */ 0);
}

static void *mem_realloc(void *ptr, size_t size)
{
	return rte_realloc(ptr, size, /* align= */ 0);
}

static void mem_free(void *ptr)
{
	rte_free(ptr);
}

#endif /* end of #if MEM_ALLOC_PROVIDER */

#endif /* end of #ifndef _MEM_ALLOC_H */

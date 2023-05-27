#ifndef _SPDK_THREAD_H_
#define _SPDK_THREAD_H_

typedef unsigned long lkl_thread_t;

int spdk_spawn_poll_thread(lkl_thread_t **thread, void (*fn)(void *),
			   void *arg);
int spdk_join_poll_thread(lkl_thread_t *thread);
// defined in src/lkl/spdk.c
void spdk_yield_thread(void);

#endif

#define _GNU_SOURCE
#include <pthread.h>
#include "thread.h"

int spdk_spawn_poll_thread(lkl_thread_t **thread, void (*fn)(void *), void *arg)
{
	int res = pthread_create((pthread_t *)thread, NULL,
				 (void *(*)(void *))fn, arg);
	pthread_setname_np((pthread_t)(*thread), "spdk");
	return res;
}

int spdk_join_poll_thread(lkl_thread_t *thread)
{
	return pthread_join((pthread_t)thread, NULL);
}

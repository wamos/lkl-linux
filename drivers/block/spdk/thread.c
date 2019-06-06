#include <pthread.h>
#include "thread.h"

lkl_thread_t spdk_spawn_poll_thread(lkl_thread_t *thread, void (*fn)(void *),
				    void *arg)
{
	return pthread_create((pthread_t *)thread, NULL, (void *(*)(void *))fn,
			      arg);
}

int spdk_join_poll_thread(lkl_thread_t thread)
{
	return pthread_join((pthread_t)thread, NULL);
}

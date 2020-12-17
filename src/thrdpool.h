#ifndef _THRDPOOL_H
#define _THRDPOOL_H

typedef struct tpool_s tpool_t;

tpool_t *tpool_create(__const__ int size);

int tpool_add_task(tpool_t *tpool, void *(*fun)(void *), void *arg);

int tpool_destroy(tpool_t *tpool);

#endif

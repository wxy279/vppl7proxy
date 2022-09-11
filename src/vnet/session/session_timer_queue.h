#ifndef SRC_VNET_SESSION_SESSION_TIMER_QUEUE_H_
#define SRC_VNET_SESSION_SESSION_TIMER_QUEUE_H_

#include <bsd/sys/queue.h>
#include <vppinfra/time.h>

#define TIMER_HEAD(name, type) \
struct name { \
    TAILQ_HEAD(click_timer_head_##name, type) t_head; \
    u64 *t_timeout; \
    int t_numitems; \
    uint32_t t_flag; \
}

#define TIMER_HEAD_INITIALIZER(head) \
	{ TAILQ_HEAD_INITIALIZER(head.t_head), NULL, 0 , 0}

#define TIMER_HEAD_INIT(head) \
do	{TAILQ_INIT(&(head).t_head); \
	(head).t_timeout = NULL; \
	(head).t_numitems = 0; \
	(head).t_flag = 0; \
}while(0)

#define TIMER_SET_TIMEVAR(head, var) (head).t_timeout = &var

#define TIMER_SET_TIMEVARP(head, var_p) (head).t_timeout = var_p

#define TIMER_SET_FLAG(head, flag)  (head).t_flag |= flag

#define TIMER_NUMITEMS(head) ((head)->t_numitems)

#define TIMER_ENTRY(type) \
struct { \
    struct type *tqe_next; \
    struct type **tqe_prev; \
    u64 t_expire; \
}
#define TIMER_FIRST(head)	TAILQ_FIRST(&(head).t_head)
#define TIMER_FOREACH(var, head, field)	TAILQ_FOREACH(var, &(head)->t_head, field)
#define TIMER_FOREACH_SAFE(var, head, field, tvar)	TAILQ_FOREACH_SAFE(var, &(head)->t_head, field, tvar)


#define TIMER_ACTIVE(item, field)	((item)->field.tqe_prev)
#define TIMER_INIT(item, field)	do { (item)->field.tqe_prev = NULL; } while (0)

#define TIMER_RESET(item, queue, field)	\
do {							\
    if (TIMER_ACTIVE(item, field)) {			\
	_TIMER_REMOVE(queue, item, field);		\
    }							\
    (item)->field.t_expire = clib_cpu_time_now();			\
    TAILQ_INSERT_TAIL(&((queue)->t_head), item, field); \
    (queue)->t_numitems++;				\
} while (0)

#define TIMER_STOP(item, queue, field)			\
do {							\
    if (TIMER_ACTIVE(item, field)) {			\
		_TIMER_REMOVE(queue, item, field);		\
	}                                       \
    TIMER_INIT(item, field);				\
} while (0)

#define _TIMER_REMOVE(queue, item, field)		\
do {							\
    TAILQ_REMOVE(&((queue)->t_head), item, field);	\
    (queue)->t_numitems--;				\
} while (0)

#define TIMER_TAILQ_STOP(item, queue, field)			\
do {							\
    if (TIMER_ACTIVE(item, field)) {			\
	TAILQ_REMOVE(&(queue), item, field);		\
    }							\
    TIMER_INIT(item, field);				\
} while (0)

#define TIMER_EXPIRES_IN(item, queue, field) \
	(((item->field.t_expire + *((queue)->t_timeout)) - clib_cpu_time_now()))

#define TIMER_EXPIRED(item, queue, field) \
	(((item = TAILQ_FIRST(&((queue)->t_head))) == NULL) ? (NULL) : \
	((TIMER_EXPIRES_IN(item, queue, field) > 0) ? \
	 (item = NULL) : (item)))

/*self defined queue start*/

typedef struct my_ngx_queue_s  my_ngx_queue_t;

struct my_ngx_queue_s {
    my_ngx_queue_t  *prev;
    my_ngx_queue_t  *next;
};


#define my_ngx_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q


#define my_ngx_queue_empty(h)                                                    \
    (h == (h)->prev)


#define my_ngx_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


#define my_ngx_queue_insert_after   my_ngx_queue_insert_head


#define my_ngx_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x


#define my_ngx_queue_head(h)                                                     \
    (h)->next


#define my_ngx_queue_last(h)                                                     \
    (h)->prev


#define my_ngx_queue_sentinel(h)                                                 \
    (h)


#define my_ngx_queue_next(q)                                                     \
    (q)->next


#define my_ngx_queue_prev(q)                                                     \
    (q)->prev


#if (NGX_DEBUG)

#define my_ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

#define my_ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


#define my_ngx_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;


#define my_ngx_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;


#define my_ngx_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))


my_ngx_queue_t *my_ngx_queue_middle(my_ngx_queue_t *queue);
void my_ngx_queue_sort(my_ngx_queue_t *queue,
    int (*cmp)(const my_ngx_queue_t *, const my_ngx_queue_t *));

/*self define queue end*/

#endif /*SRC_VNET_SESSION_SESSION_TIMER_QUEUE_H_*/

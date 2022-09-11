/*
 * Copyright (c) GuangweiCao.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __HILI_HTTP_H__
#define __HILI_HTTP_H__

#include <bsd/sys/queue.h>
#include <vnet/session/session_types.h>
#include <vnet/session/session.h>
#include <vnet/session/session_lookup.h>
#include <vnet/session/transport.h>
#include <vnet/session/session_debug.h>

#include <vnet/session/session_timer_queue.h>

#include <vnet/http_proxy/nginx/include/ngx_http.h>
#include <vnet/http_proxy/http_error_def.h>


#include <vnet/http_proxy/http_parse.h>

#define dproxy_version      1000000
#define DPROXY_VERSION      "1.0.0"
#define DPROXY_VER          "vpphttpproxy/" DPROXY_VERSION

#define DPROXY_HTTP_ERROR(http_data, val) 			\
do {								\
	if ((http_data) != NULL)  {				\
		if ((http_data)->rst_code == 0)  {		\
			(http_data)->rst_code = (val); 	\
		};						\
	};							\
	return NGX_ERROR;					\
} while (0)

#define RST_APP_ID_HTTP         0x0600
#define RST_APP_ID_HTTP2         0x0700
#define RST_APP_ID_HTTP3         0x0800

#define RST_ID_FROM_HTTP_1 (RST_APP_ID_HTTP + 0x1)
#define RST_ID_FROM_HTTP_2 (RST_APP_ID_HTTP + 0x2)
#define RST_ID_FROM_HTTP_3 (RST_APP_ID_HTTP + 0x3)
#define RST_ID_FROM_HTTP_4 (RST_APP_ID_HTTP + 0x4)
#define RST_ID_FROM_HTTP_5 (RST_APP_ID_HTTP + 0x5)
#define RST_ID_FROM_HTTP_6 (RST_APP_ID_HTTP + 0x6)
#define RST_ID_FROM_HTTP_7 (RST_APP_ID_HTTP + 0x7)

typedef int (*dproxy_http_upstream_handler_pt)(session_t *ups);

#define DP_UPSTREAM_USE_KEEPALIVE	0x01

typedef struct dproxy_http_upstream_s {
	int tmp;
	int 		content_length_exists:1;
	int			is_chunked:1;
	int 		content_length;
	int 		current_body_length;
	uint64_t	dp_ups_flags;
	u8	thread_index;
	u32 dp_ups_index;
	session_t *peer;
	http_parse_data_t *http_data;
	dproxy_http_upstream_handler_pt     read_event_handler;
	dproxy_http_upstream_handler_pt     write_event_handler;
	//struct rte_mempool      *mpool;
	PARSE_STATE_e   current_parse_state;
	vlib_buffer_t *parsing_resp_mb;
	vlib_buffer_t *resp_next_mb;
	vlib_buffer_t *last_parsed_mbuf;
	CLIB_CACHE_LINE_ALIGN_MARK (pad);
} dproxy_http_upstream_t;

typedef struct __ngx_http_upstream_wrapper {
	u8	thread_index;
	u32 ng_upswr_index;
	ngx_http_upstream_t http_upstream;
	CLIB_CACHE_LINE_ALIGN_MARK (pad);
} ngx_http_upstream_wrapper_t;


int dproxy_http_input_empty(vlib_main_t *vm, session_t *conn);
//int dproxy_http_input(session_t *conn);
int dproxy_http_request_handler(session_t *conn);
int dproxy_http_upstream_handler(session_t *conn);

void dproxy_http_longest_transiction_check(void);

int dproxy_http_init(void);
int dproxy_http_term(void);


typedef struct _htproxy_data_manager_main_t
{
	/** Per worker thread tls conn pools */
	http_parse_data_t **http_parse_data_pools;
	/** Per worker-thread tls connection pool peekers rw locks */
	clib_rwlock_t *http_parse_data_peekers_rw_locks;
	/** Per worker thread tls record pools */
	dproxy_http_upstream_t **htproxy_upstream_pools;
	clib_rwlock_t *htproxy_upstream_peekers_rw_locks;

	ngx_http_upstream_wrapper_t **htproxy_ngx_upstream_pools;
	clib_rwlock_t *htproxy_ngx_upstream_peekers_rw_locks;

	my_ngx_queue_t *ups_session_cache;
	my_ngx_queue_t *req_session_cache;

	u8 is_enabled;
	uword nouse1;
	/** Preallocate session config parameter */
	u32 preallocated_http_pdata;

	u32 preallocated_htproxy_upstream;
	u32 preallocated_ngx_upstream;
}htproxy_data_manager_main_t;

extern htproxy_data_manager_main_t htproxy_data_manager_main;

/*http parse data functions declare*/
always_inline u8
http_data_is_valid (u32 si, u8 thread_index)
{
	FUNC_TRACE;
	http_parse_data_t *s;
	s = pool_elt_at_index (htproxy_data_manager_main.http_parse_data_pools[thread_index], si);
	if (s->thread_index != thread_index || s->http_data_index != si) {
		ft_printf("s->thread_index != thread_index || s->http_data_index != si and return 0\n");
		LINE_TRACE;
		return 0;
	}
	return 1;
}

always_inline http_parse_data_t *
http_data_get (u32 si, u32 thread_index)
{
	FUNC_TRACE;
	ASSERT (http_data_is_valid (si, thread_index));
	return pool_elt_at_index (htproxy_data_manager_main.http_parse_data_pools[thread_index], si);
}

always_inline http_parse_data_t *
http_data_get_if_valid (u64 si, u32 thread_index)
{
	FUNC_TRACE;
	if (thread_index >= vec_len (htproxy_data_manager_main.http_parse_data_pools)) {
		LINE_TRACE;
		ft_printf("thread_index >= vec_len (htproxy_data_manager_main.http_parse_data_pools), return NULL\n");
		return 0;
	}

	if (pool_is_free_index (htproxy_data_manager_main.http_parse_data_pools[thread_index], si)) {
		LINE_TRACE;
		ft_printf("there is no item, return NULL\n");
		return 0;
	}
	ASSERT (http_data_is_valid (si, thread_index));
	return pool_elt_at_index (htproxy_data_manager_main.http_parse_data_pools[thread_index], si);

}

http_parse_data_t * http_data_alloc(u32 thread_index);
void http_data_free(http_parse_data_t * s);

/*ngx_http_upstream_t functions declare*/

always_inline u8
ngx_http_upstream_is_valid (u32 si, u8 thread_index)
{
	FUNC_TRACE;
	ngx_http_upstream_wrapper_t *s;
	s = pool_elt_at_index (htproxy_data_manager_main.htproxy_ngx_upstream_pools[thread_index], si);
	if (s->thread_index != thread_index || s->ng_upswr_index != si) {
		ft_printf("s->thread_index != thread_index || s->ng_upswr_index != si and return 0\n");
		LINE_TRACE;
		return 0;
	}
	return 1;
}

always_inline ngx_http_upstream_t *
ngx_http_upstream_get(u32 si, u32 thread_index)
{
	FUNC_TRACE;
	ngx_http_upstream_wrapper_t *ngx_ups_wr;

	ASSERT (ngx_http_upstream_is_valid (si, thread_index));
	ngx_ups_wr = pool_elt_at_index (htproxy_data_manager_main.htproxy_ngx_upstream_pools[thread_index], si);
	return &ngx_ups_wr->http_upstream;
}

always_inline ngx_http_upstream_t *
ngx_http_upstream_get_if_valid (u64 si, u32 thread_index)
{
	FUNC_TRACE;
	ngx_http_upstream_wrapper_t *ngx_ups_wr;
	if (thread_index >= vec_len (htproxy_data_manager_main.htproxy_ngx_upstream_pools)) {
		LINE_TRACE;
		ft_printf("thread_index >= vec_len (htproxy_data_manager_main.http_parse_data_pools), return NULL\n");
		return 0;
	}

	if (pool_is_free_index (htproxy_data_manager_main.htproxy_ngx_upstream_pools[thread_index], si)) {
		LINE_TRACE;
		ft_printf("there is no item, return NULL\n");
		return 0;
	}
	ASSERT (ngx_http_upstream_is_valid (si, thread_index));
	ngx_ups_wr = pool_elt_at_index (htproxy_data_manager_main.htproxy_ngx_upstream_pools[thread_index], si);
	return &ngx_ups_wr->http_upstream;

}

ngx_http_upstream_t * ngx_http_upstream_alloc(u32 thread_index);
void ngx_http_upstream_free(ngx_http_upstream_t * s);

/*dproxy_http_upstream functions declare*/
always_inline u8
proxy_http_upstream_is_valid (u32 si, u8 thread_index)
{
	FUNC_TRACE;
	dproxy_http_upstream_t *s;
	s = pool_elt_at_index (htproxy_data_manager_main.htproxy_upstream_pools[thread_index], si);
	if (s->thread_index != thread_index || s->dp_ups_index != si) {
		ft_printf("s->thread_index != thread_index || s->dp_ups_index != si and return 0\n");
		LINE_TRACE;
		return 0;
	}
	return 1;
}

always_inline dproxy_http_upstream_t *
proxy_http_upstream_get (u32 si, u32 thread_index)
{
	FUNC_TRACE;
	ASSERT (proxy_http_upstream_is_valid (si, thread_index));
	return pool_elt_at_index (htproxy_data_manager_main.htproxy_upstream_pools[thread_index], si);
}

always_inline dproxy_http_upstream_t *
proxy_http_upstream_get_if_valid (u64 si, u32 thread_index)
{
	FUNC_TRACE;
	if (thread_index >= vec_len (htproxy_data_manager_main.htproxy_upstream_pools)) {
		LINE_TRACE;
		ft_printf("thread_index >= vec_len (htproxy_data_manager_main.http_parse_data_pools), return NULL\n");
		return 0;
	}

	if (pool_is_free_index (htproxy_data_manager_main.htproxy_upstream_pools[thread_index], si)) {
		LINE_TRACE;
		ft_printf("there is no item, return NULL\n");
		return 0;
	}
	ASSERT (proxy_http_upstream_is_valid (si, thread_index));
	return pool_elt_at_index (htproxy_data_manager_main.htproxy_upstream_pools[thread_index], si);

}

dproxy_http_upstream_t * proxy_http_upstream_alloc(u8 thread_index);
void proxy_http_upstream_free(dproxy_http_upstream_t * s);

#endif /* __HILI_HTTP_H__*/


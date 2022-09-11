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

/**
 * \file
 *
 * \author GuangweiCao <caoguangwei279@163.com>
 *
 * HTTP proxy parser and handler.
 *
 * This implements a outline of http frame of handler with client
 * and upstream side.
 */

#include <vnet/http_proxy/http_proxy.h>
#include <vnet/http_proxy/hili_minheap.h>
#include <vnet/session/session_timer_queue.h>

htproxy_data_manager_main_t htproxy_data_manager_main;

static uint16_t http_mb_id_100 = 100;

#define HTTP_MB_ID_101 (http_mb_id_100 + 1)
#define HTTP_MB_ID_102 (http_mb_id_100 + 2)

/*g_http_min_heap is use to record the largest K transiction time of a thread handled*/
static PT_Heap g_http_min_heap;
static int g_min_heap_size = 10;
static heap_entry_t g_min_heap_init_arra[10];

/*-------------star code -------------*/

static u_char dproxy_http_server_full_string[] = "Server: " DPROXY_VER CRLF;


static ngx_int_t
dproxy_http_upstream_process_headers(ngx_http_request_t *r, ngx_http_upstream_t *u);

static ngx_int_t dproxy_http_send_header(ngx_http_request_t *r, vlib_buffer_t **mb);
static void dproxy_http_upstream_send_response(vlib_main_t *vm, dproxy_http_upstream_t *upstream);
static ngx_int_t dproxy_http_header_filter(ngx_http_request_t *r, vlib_buffer_t **mb);
//static ngx_int_t dproxy_http_write_filter(ngx_http_request_t *r, struct rte_mbuf *in);
static int dproxy_http_close(http_parse_data_t *http_data);

static void dproxy_http_release_resource(session_t *conn);

int debug_htp_resp_statem = 0;
int debug_htp_req_statem = 0;
int debug_htp_ups_statem = 0;

int debug_htp_pipe_statem = 0;
int debug_htp_config_funcs = 0;
int debug_htp_shipping_funcs = 0;

static int hili_tcp_upstream_free_keepalive_peer(session_t *conn);


static ngx_str_t dproxy_http_status_lines[] = {

    ngx_string("200 OK"),
    ngx_string("201 Created"),
    ngx_string("202 Accepted"),
    ngx_null_string,  /* "203 Non-Authoritative Information" */
    ngx_string("204 No Content"),
    ngx_null_string,  /* "205 Reset Content" */
    ngx_string("206 Partial Content"),

    /* ngx_null_string, */  /* "207 Multi-Status" */

#define NGX_HTTP_LAST_2XX  207
#define NGX_HTTP_OFF_3XX   (NGX_HTTP_LAST_2XX - 200)

    /* ngx_null_string, */  /* "300 Multiple Choices" */

    ngx_string("301 Moved Permanently"),
    ngx_string("302 Moved Temporarily"),
    ngx_string("303 See Other"),
    ngx_string("304 Not Modified"),
    ngx_null_string,  /* "305 Use Proxy" */
    ngx_null_string,  /* "306 unused" */
    ngx_string("307 Temporary Redirect"),
    ngx_string("308 Permanent Redirect"),

#define NGX_HTTP_LAST_3XX  309
#define NGX_HTTP_OFF_4XX   (NGX_HTTP_LAST_3XX - 301 + NGX_HTTP_OFF_3XX)

    ngx_string("400 Bad Request"),
    ngx_string("401 Unauthorized"),
    ngx_string("402 Payment Required"),
    ngx_string("403 Forbidden"),
    ngx_string("404 Not Found"),
    ngx_string("405 Not Allowed"),
    ngx_string("406 Not Acceptable"),
    ngx_null_string,  /* "407 Proxy Authentication Required" */
    ngx_string("408 Request Time-out"),
    ngx_string("409 Conflict"),
    ngx_string("410 Gone"),
    ngx_string("411 Length Required"),
    ngx_string("412 Precondition Failed"),
    ngx_string("413 Request Entity Too Large"),
    ngx_string("414 Request-URI Too Large"),
    ngx_string("415 Unsupported Media Type"),
    ngx_string("416 Requested Range Not Satisfiable"),
    ngx_null_string,  /* "417 Expectation Failed" */
    ngx_null_string,  /* "418 unused" */
    ngx_null_string,  /* "419 unused" */
    ngx_null_string,  /* "420 unused" */
    ngx_string("421 Misdirected Request"),
    ngx_null_string,  /* "422 Unprocessable Entity" */
    ngx_null_string,  /* "423 Locked" */
    ngx_null_string,  /* "424 Failed Dependency" */
    ngx_null_string,  /* "425 unused" */
    ngx_null_string,  /* "426 Upgrade Required" */
    ngx_null_string,  /* "427 unused" */
    ngx_null_string,  /* "428 Precondition Required" */
    ngx_string("429 Too Many Requests"),

#define NGX_HTTP_LAST_4XX  430
#define NGX_HTTP_OFF_5XX   (NGX_HTTP_LAST_4XX - 400 + NGX_HTTP_OFF_4XX)

    ngx_string("500 Internal Server Error"),
    ngx_string("501 Not Implemented"),
    ngx_string("502 Bad Gateway"),
    ngx_string("503 Service Temporarily Unavailable"),
    ngx_string("504 Gateway Time-out"),
    ngx_string("505 HTTP Version Not Supported"),
    ngx_null_string,        /* "506 Variant Also Negotiates" */
    ngx_string("507 Insufficient Storage"),

    /* ngx_null_string, */  /* "508 unused" */
    /* ngx_null_string, */  /* "509 unused" */
    /* ngx_null_string, */  /* "510 Not Extended" */

#define NGX_HTTP_LAST_5XX  508

};
#if 0
#define this_reqcon_cache             (RTE_PER_LCORE(requst_connection_cache))
static RTE_DEFINE_PER_LCORE(my_ngx_queue_t, requst_connection_cache);
#endif
static void dproxy_http_trace_in_reqeust_conn(session_t *conn)
{
	//my_ngx_queue_insert_head(&this_reqcon_cache, &conn->keepalive_queue);
	htproxy_data_manager_main_t *htproxy_dmm = &htproxy_data_manager_main;
	my_ngx_queue_insert_head(&htproxy_dmm->req_session_cache[conn->thread_index], &conn->keepalive_queue);
	return;
}

static void dproxy_http_trace_out_reqeust_conn(session_t *conn)
{
	my_ngx_queue_t  *q;
	session_t *conn_tmp;
	int found = 0;
	htproxy_data_manager_main_t *htproxy_dmm = &htproxy_data_manager_main;

	if (my_ngx_queue_empty(&htproxy_dmm->req_session_cache[conn->thread_index])) {
		htp_req_debug_print("%s requst_connection_cache is empty, error happend!!!!!\n", __func__);
		return;
	}

	for (q = my_ngx_queue_head(&htproxy_dmm->req_session_cache[conn->thread_index]);
			q != my_ngx_queue_sentinel(&htproxy_dmm->req_session_cache[conn->thread_index]);
				q = my_ngx_queue_next(q)) {

		conn_tmp = my_ngx_queue_data(q, session_t, keepalive_queue);
		if (conn_tmp == conn) {
			found = 1;
			htp_req_debug_print("%s get the conn from requst_connection_cache \n", __func__);
		}
	}
	if (found) {
		my_ngx_queue_remove(&conn->keepalive_queue);
	} else {
		htp_req_debug_print("%s not found this conn in requst_connection_cache\n", __func__);
	}
	return;
}

static int dproxy_http_keepalive_handler(session_t *conn)
{
	FUNC_TRACE;
	if (conn->hili_flags & SS_TCP_RESET || conn->hili_flags & SS_TCP_APPTERM) {
		htp_req_debug_print("%s TCP RESET or APP TERM, so request conn say_goodbye\n", __func__);
		goto say_goodbye;
	}

	if ((conn->hili_flags & (SS_TCP_RECV_FISRT_FIN | SS_TCP_RECV_SECOND_FIN))) {
		htp_req_debug_print("%s TCP RECV FISRT FIN or TCP RECV SECOND FIN, so reqeust conn say_goodbye\n", __func__);
		if (hili_session_has_data(conn)) {
			htp_req_debug_print("%s session has data\n", __func__);
		}
		goto say_goodbye;
	}

	htp_req_debug_print("%s request side connection reuse, start to wait request line \n", __func__);
	conn->rx_cb_func = dproxy_http_input;
	dproxy_http_trace_out_reqeust_conn(conn);
	conn->rx_cb_func(conn);
	return EHTTP_OK;

say_goodbye:
	dproxy_http_trace_out_reqeust_conn(conn);
	conn->rx_cb_func = NULL;
	return EHTTP_OK;
}

static void hili_tcp_remove_keepalive_conn(session_t *conn)
{
	my_ngx_queue_t  *q;
	session_t *conn_tmp;
	int found = 0;
	htproxy_data_manager_main_t *htproxy_dmm = &htproxy_data_manager_main;
	if (ngx_queue_empty(&htproxy_dmm->ups_session_cache[conn->thread_index])) {
		htp_ups_debug_print("%s upstream_conn_cache is empty, error happend!!!!!\n", __func__);
		return;
	}

	for (q = ngx_queue_head(&htproxy_dmm->ups_session_cache[conn->thread_index]);
			q != ngx_queue_sentinel(&htproxy_dmm->ups_session_cache[conn->thread_index]);
				q = ngx_queue_next(q)) {

		conn_tmp = ngx_queue_data(q, session_t, keepalive_queue);
		if (conn_tmp == conn) {
			found = 1;
			htp_ups_debug_print("%s get the conn from upstream_conn_cache \n", __func__);
		}
	}
	if (found) {
		ngx_queue_remove(&conn->keepalive_queue);
	} else {
		htp_ups_debug_print("%s not found this conn in upstream_conn_cache\n", __func__);
	}
	return;
}

static int dproxy_http_upstream_keepalive_close_handler(session_t *conn)
{
	FUNC_TRACE;
	if (conn->hili_flags & SS_TCP_RESET || conn->hili_flags & SS_TCP_APPTERM) {
		htp_ups_debug_print("%s TCP RESET or APP TERM so upstream conn say_goodbye\n", __func__);
		goto say_goodbye;
	}

	if ((conn->hili_flags & (SS_TCP_RECV_FISRT_FIN | SS_TCP_RECV_SECOND_FIN))) {
		htp_ups_debug_print("%s TCP RECV FISRT FIN or TCP RECV SECOND FIN, so upstream conn say_goodbye\n", __func__);
		if (hili_session_has_data(conn)) {
			htp_ups_debug_print("%s session has data, but still close upstream keepalive conn\n", __func__);
		}
		goto say_goodbye;
	}

	htp_ups_debug_print("%s something trigger the in keepalive state connection, please attention!!!\n", __func__);
	return EHTTP_OK;

say_goodbye:
	hili_tcp_remove_keepalive_conn(conn);
	conn->rx_cb_func = NULL;
	return EHTTP_OK;
}

static int
dproxy_http_upstream_free_keepalive(http_parse_data_t *http_data, dproxy_http_upstream_t *upstream)
{
	FUNC_TRACE;
	session_t *conn = upstream->peer;
	ngx_http_upstream_t *ngx_upstream = http_data->req.upstream;

	if (ngx_upstream->keepalive) {
		htp_ups_debug_print("%s:%d upstream with keepalive\n", __func__, __LINE__);
		if (conn->cons_side) {
			((session_t *)conn->cons_side)->cons_side = NULL;
			conn->cons_side = NULL;
		}
		/*upstream objs give the request side to cleanup*/
		conn->rx_cb_func = dproxy_http_upstream_keepalive_close_handler;
		hili_tcp_upstream_free_keepalive_peer(conn);
	} else {
		if (upstream->dp_ups_flags & DP_UPSTREAM_USE_KEEPALIVE) {
			htp_ups_debug_print("%s:%d dp_upstream set keepalive, but upstream don't set, maybe version < 11 or connection:close by server\n", __func__, __LINE__);
		}
		htp_ups_debug_print("%s:%d upstream without keepalive\n", __func__, __LINE__);
	}

	return EHTTP_OK;
}

static void dproxy_http_request_free_pipe(session_t *pipe)
{
#if 0
	dproxy_session_cleanup(pipe);
	dproxy_session_free(pipe);
#endif
	hili_session_cleanup(pipe);
	session_free(pipe);
}

static void dproxy_http_request_free_upstream(vlib_main_t *vm, dproxy_http_upstream_t *dp_upstream)
{
	if (dp_upstream->parsing_resp_mb && dp_upstream->parsing_resp_mb != dp_upstream->resp_next_mb) {
		//dproxy_mbuf_free_memtrace(dp_upstream->parsing_resp_mb);
		vlib_buffer_hili_free_one_buffer(vm, dp_upstream->parsing_resp_mb);
		dp_upstream->parsing_resp_mb = NULL;
	}
	if (dp_upstream->resp_next_mb) {
		//dproxy_mbuf_free_memtrace(dp_upstream->resp_next_mb);
		vlib_buffer_hili_free_one_buffer(vm, dp_upstream->resp_next_mb);
		dp_upstream->resp_next_mb = NULL;
	}
	//dproxy_http_req_upstream_free(dp_upstream);
	proxy_http_upstream_free(dp_upstream);
}

static int
dproxy_http_request_free_keepalive(vlib_main_t *vm, http_parse_data_t *http_data)
{
	FUNC_TRACE;
	session_t *conn = http_data->reqcon;
	ngx_http_request_t *request = &http_data->req;
	dproxy_http_upstream_t *dp_upstream = http_data->upstream;
	session_t *lpipe, *rpipe;

	if (request->keepalive) {
		htp_req_debug_print("%s:%d request finalize with keepalive\n", __func__, __LINE__);
		if (conn->cons_side) {
			((session_t *)conn->cons_side)->cons_side = NULL;
			conn->cons_side = NULL;
		}
		lpipe = http_data->pipe;
		rpipe = lpipe->fwds;
		dproxy_http_request_free_pipe(lpipe);
		dproxy_http_request_free_pipe(rpipe);
		http_data->pipe = NULL;
		dproxy_http_request_free_upstream(vm, dp_upstream);
		http_data->upstream = NULL;
		//ngx_http_req_upstream_free(conn->http_data->req.upstream);
		ngx_http_upstream_free(conn->http_data->req.upstream);
		conn->http_data->req.upstream = NULL;

		//dproxy_http_parse_data_free(conn->http_data);
		http_data_free(conn->http_data);
		conn->http_data = NULL;

		conn->rx_cb_func = dproxy_http_keepalive_handler;
		dproxy_http_trace_in_reqeust_conn(conn);
		// TODO add request side connection to specified queue for drain later ?
	} else {
		htp_req_debug_print("%s:%d request finalize without keepalive\n", __func__, __LINE__);
	}
	return EHTTP_OK;
}

static inline void dproxy_http_set_4tuple(hed_4tuple_t * tup_info, session_t *conn)
{
	transport_connection_t *tc;
	tc = session_get_transport(conn);

	tup_info->local_ip = tc->lcl_ip.ip4.as_u32;
	tup_info->remote_ip = tc->rmt_ip.ip4.as_u32;
	tup_info->local_port = tc->lcl_port;
	tup_info->remote_port = tc->rmt_port;
}

static void
dproxy_http_finalize_request(vlib_main_t *vm, http_parse_data_t *http_data, ngx_http_request_t *r, ngx_int_t rc)
{
	session_t *req_conn, *ups_conn;
	hed_8tuple_t *two_conn_info;
	uint64_t now = clib_cpu_time_now();
	uint64_t diff = now - http_data->req_start_time;
	heap_entry_t *new_hentry, *heap_top_entry, *top_tmp;
	heap_top_entry = getHeapTop(g_http_min_heap);
	return;//if not will panic for reason commened as follow TOOD
	if (diff > heap_top_entry->key) {
		top_tmp = popHeap(g_http_min_heap);
		if (top_tmp != heap_top_entry) {
			clib_panic("Unkonw error happend, top_tmp != heap_top_entry\n");
		}
		new_hentry = clib_mem_alloc_aligned(sizeof(heap_entry_t) + sizeof(hed_8tuple_t), CLIB_CACHE_LINE_BYTES);
		if (new_hentry == NULL) {
			return;
		}
		req_conn = http_data->reqcon;
		ups_conn = http_data->upstream->peer;

		two_conn_info = (hed_8tuple_t *)new_hentry->entry_data;
		dproxy_http_set_4tuple(&two_conn_info->req_info, req_conn);
		dproxy_http_set_4tuple(&two_conn_info->ups_info, ups_conn);

		new_hentry->key = diff;
		pushHeap(g_http_min_heap, new_hentry);
		clib_mem_free(heap_top_entry);//TODO if want use this later, should imp g_http_min_heap as per-thread, if not here will panic because it's not satisfied clib_mem_get_per_cpu_heap
	}
    return;
	dproxy_http_upstream_free_keepalive(http_data, http_data->upstream);
	dproxy_http_request_free_keepalive(vm, http_data);
}

static void
dproxy_http_upstream_finalize_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_int_t rc)
{
	FUNC_TRACE;
}

always_inline int
hili_session_proxy_pre_check(session_t *hili_ss)
{
	FUNC_TRACE;
	u64 local_ctrl_flags;

	if (hili_ss->hili_flags & SS_TCP_APPBREAKUP) {
		htp_ship_debug_print("break up");
		session_log_debug("break up");
		return -1;
	}

	if (hili_ss->cons_side == NULL) {
		htp_ship_debug_print("hili_ss->cons_side == NULL");
		session_log_debug("hili_ss->cons_side == NULL");
		LINE_TRACE;
		return -1;
	}
#if 1
	if (hili_session_tx_not_ready(hili_ss->cons_side)) {
		htp_ship_debug_print("consum side not ready");
		session_log_debug("consum side not ready");
		return -1;
	}
#endif
	return 0;
}

always_inline int
hili_session_proxy_exchange_data(session_t *hili_ss)
{
	FUNC_TRACE;
	vlib_main_t *vm = vlib_get_main();
	vlib_buffer_t *vbp;
	int len;

	if (hili_session_send_window(hili_ss->cons_side) > 0) {
		len = hili_session_read(vm, hili_ss, &vbp);
		if (len > 0) {
			hili_buffer_trace_print(vbp);
			if (hili_session_write(vm, hili_ss->cons_side, vbp, len) < 0) {
				return -1;
			}
		} else {
			htp_ship_debug_print("read length <= 0");
			session_log_debug("read length <= 0");
		}
	} else {
		htp_ship_debug_print("hili_ss->cons_side send window <= 0");
		session_log_debug("hili_ss->cons_side send window <= 0");
	}

	if (hili_session_send_window(hili_ss) > 0) {
		len = hili_session_read(vm, hili_ss->cons_side, &vbp);
		if (len > 0) {
			hili_buffer_trace_print(vbp);
			if (hili_session_write(vm, hili_ss, vbp, len) < 0) {
				return -1;
			}
		} else {
			htp_ship_debug_print("read length <= 0");
			session_log_debug("read length <= 0");
		}
	} else {
		htp_ship_debug_print("hili_ss send window <= 0");
		session_log_debug("hili_ss send window <= 0");
	}

	return 0;
}

always_inline int
hili_session_proxy_propagate_event(session_t *hili_ss)
{
	FUNC_TRACE;
	session_cur_status_t cur_status;

	cur_status = hili_session_current_status(hili_ss);
	if (cur_status > HILI_SESSION_CUR_STABLE) {
		htp_ship_debug_print("cur_state > HILI_SESSION_CUR_STABLE");
		session_log_debug("cur_state > HILI_SESSION_CUR_STABLE");
		if (hili_session_send_window(hili_ss->cons_side) >= 0) {
			hili_session_halfclose(hili_ss->cons_side);
		}
	} else if (cur_status < HILI_SESSION_CUR_STABLE) {
		htp_ship_debug_print("cur_state < HILI_SESSION_CUR_STABLE");
		session_log_debug("cur_state < HILI_SESSION_CUR_STABLE");
		((session_t *)hili_ss->cons_side)->cons_side = NULL;
		hili_session_terminate(hili_ss->cons_side , 2);
		hili_ss->rx_cb_func = NULL;
	}

	cur_status = hili_session_current_status(hili_ss->cons_side);
	if (cur_status > HILI_SESSION_CUR_STABLE) {
		htp_ship_debug_print("cur_state > HILI_SESSION_CUR_STABLE");
		session_log_debug("cur_state > HILI_SESSION_CUR_STABLE");
		if (hili_session_send_window(hili_ss) >= 0) {
			hili_session_halfclose(hili_ss);
		}
	} else if (cur_status < HILI_SESSION_CUR_STABLE) {
		htp_ship_debug_print("cur_state < HILI_SESSION_CUR_STABLE");
		session_log_debug("cur_state < HILI_SESSION_CUR_STABLE");
		hili_session_terminate(hili_ss , 3);
		hili_ss->rx_cb_func = NULL;
	}

	return 0;
}

always_inline void
hili_session_proxy_forward_breakup(session_t *hili_ss)
{
	hili_ss->hili_flags |= SS_TCP_APPBREAKUP;
	((session_t *)hili_ss->cons_side)->hili_flags |= SS_TCP_APPBREAKUP;
}

always_inline int
hili_session_proxy_post_handle(session_t *hili_ss)
{
	FUNC_TRACE;
	if (hili_session_is_leaving(hili_ss) || hili_session_is_leaving(hili_ss->cons_side)) {
		hili_session_proxy_forward_breakup(hili_ss);
	}
	return 0;
}

static int
htproxy_session_forward_handler(session_t *hili_ss)
{
	FUNC_TRACE;
	htp_ship_debug_print("Enter");
#if 0
	if (hili_session_proxy_setup_consumer(hili_ss)) {
		return -1;
	}
#endif
	if (hili_session_proxy_pre_check(hili_ss)) {
		return -1;
	}

	if (hili_session_proxy_exchange_data(hili_ss)) {
		return -1;
	}

	if (hili_session_proxy_propagate_event(hili_ss)) {
		return -1;
	}

	hili_session_proxy_post_handle(hili_ss);

	return 0;
}


/*It's sure just break up breakup_mbuf*/
static inline vlib_buffer_t *dproxy_http_split_requests(vlib_main_t *vm, session_t *conn, vlib_buffer_t *breakup_mbuf, uint32_t len)
{
	uint16_t remain_len;
	u32 left_total_len;
	char *newmp_data;
	vlib_buffer_t *left_mb;
	vlib_buffer_t *parsing_mb;
	vlib_buffer_t *next_mb;
	struct http_parse_data_s *httpdata = conn->http_data;

	next_mb = vlib_get_next_buffer(vm, breakup_mbuf);

	parsing_mb = httpdata->parsing_req_mb;

	remain_len = breakup_mbuf->current_length - len;

	//left_mb = rte_pktmbuf_alloc(pktmbuf_pool[rte_socket_id()]);
	left_mb = hili_create_one_mbuf(0, VLIB_BUFFER_ALLOC_ID_HTTP_400);
	if (left_mb == NULL) {
		//curth_myhttp_stats.dproxy_myhttp_stats_no_mbuf++;
		return NULL;
	}

	newmp_data = vlib_buffer_hili_append(vm, left_mb, remain_len);
	clib_memcpy_fast(newmp_data, vlib_buffer_hili_mtod_offset(breakup_mbuf, char *, len), remain_len);
	if (next_mb) {
		vlib_buffer_hili_chain(vm, left_mb, next_mb);
	}

	//breakup_mbuf->data_len = len;
	breakup_mbuf->current_length = len;
	breakup_mbuf->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
	breakup_mbuf->flags &= ~VLIB_BUFFER_NEXT_PRESENT; 	
	breakup_mbuf->total_length_not_including_first_buffer = 0;


	//breakup_mbuf->pkt_len = len;
	//breakup_mbuf->next = NULL;
	left_total_len = vlib_buffer_length_in_chain(vm, left_mb);
	if (parsing_mb->total_length_not_including_first_buffer > left_total_len) {
		parsing_mb->total_length_not_including_first_buffer -= left_total_len;
	}

	DEBUG_DUMP_SESSION_VLIB_BUFFER("return mbuf", parsing_mb);
	
	DEBUG_DUMP_SESSION_VLIB_BUFFER("left mbuf", left_mb);
	
	session_log_debug("leave function %s\n", __func__);


	return left_mb;
}

static inline vlib_buffer_t *dproxy_http_split_responses(vlib_main_t *vm, dproxy_http_upstream_t *upstream, vlib_buffer_t *breakup_mbuf, uint32_t len)
{
	uint16_t remain_len;
	u32 left_total_len;
	char *newmp_data;
	vlib_buffer_t *left_mb;
	vlib_buffer_t *parsing_mb;
	vlib_buffer_t *next_mb;
	//struct http_parse_data_s *httpdata = conn->cons_side;

	next_mb = vlib_get_next_buffer(vm, breakup_mbuf);

	parsing_mb = upstream->parsing_resp_mb;

	remain_len = breakup_mbuf->current_length - len;

	//left_mb = rte_pktmbuf_alloc(pktmbuf_pool[rte_socket_id()]);
	left_mb = hili_create_one_mbuf(0, VLIB_BUFFER_ALLOC_ID_HTTP_401);
	if (left_mb == NULL) {
		//curth_myhttp_stats.dproxy_myhttp_stats_no_mbuf++;
		return NULL;
	}

	newmp_data = vlib_buffer_hili_append(vm, left_mb, remain_len);
	clib_memcpy_fast(newmp_data, vlib_buffer_hili_mtod_offset(breakup_mbuf, char *, len), remain_len);
	if (next_mb) {
		vlib_buffer_hili_chain(vm, left_mb, next_mb);
	}

	//breakup_mbuf->data_len = len;
	breakup_mbuf->current_length = len;
	breakup_mbuf->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
	breakup_mbuf->flags &= ~VLIB_BUFFER_NEXT_PRESENT;	
	breakup_mbuf->total_length_not_including_first_buffer = 0;


	//breakup_mbuf->pkt_len = len;
	//breakup_mbuf->next = NULL;
	if (breakup_mbuf != parsing_mb) {
		left_total_len = vlib_buffer_length_in_chain(vm, left_mb);
		if (parsing_mb->total_length_not_including_first_buffer > left_total_len) {
			parsing_mb->total_length_not_including_first_buffer -= left_total_len;
		}
	}
	DEBUG_DUMP_SESSION_VLIB_BUFFER("return mbuf", parsing_mb);
	
	DEBUG_DUMP_SESSION_VLIB_BUFFER("left mbuf", left_mb);
	
	session_log_debug("leave function %s\n", __func__);

	return left_mb;
}



static void dproxy_http_parse_set_next_parse_data_position(
	vlib_main_t *vm,
	unsigned char *processed_data_end_position,
	vlib_buffer_t **input_mbuf,
	unsigned char **cur_buff,
	int *cur_buff_len, http_parse_data_t *parse_data)
{
	if(*cur_buff_len != 0){
		*cur_buff = processed_data_end_position;
	} else {
		parse_data->last_parsed_mbuf = *input_mbuf;
		//*input_mbuf = (*input_mbuf)->next;
		*input_mbuf = vlib_get_next_buffer(vm, *input_mbuf);
		if(!(*input_mbuf)) {
			htp_req_debug_print("%s: mbuf %p parse to end, no next mbuf\n", __FUNCTION__, parse_data->last_parsed_mbuf);
			*cur_buff = NULL;
			*cur_buff_len = 0;
		} else {
			htp_req_debug_print("%s: mbuf %p parse to end, read next mbuf %p.\n", __FUNCTION__, parse_data->last_parsed_mbuf, *input_mbuf);
			*cur_buff = vlib_buffer_hili_mtod(*input_mbuf, unsigned char *);
			//*cur_buff_len = rte_pktmbuf_data_len(*input_mbuf);
			*cur_buff_len = (*input_mbuf)->current_length;
		}
	}
}

static void dproxy_http_parse_set_next_parse_resp_position(
	vlib_main_t *vm,
	unsigned char *processed_data_end_position,
	vlib_buffer_t **input_mbuf,
	unsigned char **cur_buff,
	int *cur_buff_len, dproxy_http_upstream_t *parse_data)
{
	if(*cur_buff_len != 0){
		*cur_buff = processed_data_end_position;
	} else {
		parse_data->last_parsed_mbuf = *input_mbuf;
		//*input_mbuf = (*input_mbuf)->next;
		*input_mbuf = vlib_get_next_buffer(vm, *input_mbuf);
		if(!(*input_mbuf)) {
			htp_resp_debug_print("%s: mbuf %p parse to end, no next mbuf\n", __FUNCTION__, parse_data->last_parsed_mbuf);
			*cur_buff = NULL;
			*cur_buff_len = 0;
		} else {
			htp_resp_debug_print("%s: mbuf %p parse to end, read next mbuf %p.\n", __FUNCTION__, parse_data->last_parsed_mbuf, *input_mbuf);
			*cur_buff = vlib_buffer_hili_mtod(*input_mbuf, unsigned char *);
			//*cur_buff_len = rte_pktmbuf_data_len(*input_mbuf);
			*cur_buff_len = (*input_mbuf)->current_length;
		}
	}
}

static int dproxy_http_parse_request_message(vlib_main_t *vm, session_t *conn, vlib_buffer_t *input_mbuf, vlib_buffer_t **left_mbuf)
{
	unsigned char *cur_buff = NULL;
	int cur_buff_len = 0;
	http_parse_data_t *parse_data = conn->http_data;

	*left_mbuf = input_mbuf;
	//skip leading empty mbuf;
	while (input_mbuf != NULL && input_mbuf->current_length == 0) {
		//input_mbuf	= input_mbuf->next;
		input_mbuf = vlib_get_next_buffer(vm, input_mbuf);
	}

	if (parse_data->last_parsed_mbuf) {
		//input_mbuf = parse_data->last_parsed_mbuf->next;
		input_mbuf = vlib_get_next_buffer(vm, parse_data->last_parsed_mbuf);
		if (input_mbuf == NULL) {
			htp_req_debug_print("%s last_parsed_mbuf next is NULL return PARSE_INCOMPLETE\n", __func__);
			return EHTTP_CUR_INPUT_MESSAGE_PARSE_INCOMPLETE;
		} else {
			htp_req_debug_print("%s input_mbuf start from last_parsed_mbuf next\n",__func__);
		}
	}

	if (input_mbuf == NULL) {
		htp_req_debug_print("%s input_mbuf is empty return PARSE_ERROR\n", __func__);
		return EHTTP_CUR_INPUT_MESSAGE_PARSE_ERROR;
	}

	cur_buff = vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
	//cur_buff_len = rte_pktmbuf_data_len(input_mbuf);
	cur_buff_len = input_mbuf->current_length;
	while (cur_buff != NULL && cur_buff_len > 0) {
		int ret = 0;
		unsigned char *input_mbuf_list_firstp;
		unsigned char *processed_data_end_position = NULL;
		ret = http_parse_request(input_mbuf, cur_buff, cur_buff_len, conn->http_data, &processed_data_end_position);

		if(processed_data_end_position != NULL) {
			input_mbuf_list_firstp = vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
			//cur_buff_len = input_mbuf_list_firstp + rte_pktmbuf_data_len(input_mbuf) - processed_data_end_position;
			cur_buff_len = input_mbuf_list_firstp + input_mbuf->current_length - processed_data_end_position;
			htp_req_debug_print("%s cur_buff_len %d\n", __func__, cur_buff_len);
		} else {
			cur_buff_len = 0;
			htp_req_debug_print("%s cur_buff_len %d\n", __func__, cur_buff_len);
		}

		switch(ret) {
			case EHTTP_MESSAGE_PARSE_PARAM_ERROR:
			case EHTTP_MESSAGE_PARSE_ERROR:
				return EHTTP_CUR_INPUT_MESSAGE_PARSE_ERROR;
			case EHTTP_MESSAGE_PARSE_COMPLETED:
				/*It's body return, body had been parse complete*/
			case EHTTP_HEADER_DONE_NOBY_PARSE_COMPLETED:
				/*Ngx tell header parse done and content-len == 0*/
				//if((input_mbuf->next == NULL) && (cur_buff_len == 0)) {
				if(!(input_mbuf->flags & VLIB_BUFFER_NEXT_PRESENT) && (cur_buff_len == 0)) {
					*left_mbuf = NULL;
				} else if(cur_buff_len == 0) {
					//*left_mbuf = input_mbuf->next;
					*left_mbuf = vlib_get_next_buffer(vm, input_mbuf);
					//curth_myhttp_stats.dproxy_myhttp_stats_mulreq_pkt++;
					if(*left_mbuf) {
						//input_mbuf->next = NULL;
						input_mbuf->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
					}
				} else {
					//curth_myhttp_stats.dproxy_myhttp_stats_mulreq_pkt++;
#if 1
					uint32_t offset = processed_data_end_position - vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
					//*left_mbuf = m_split(input_mbuf, offset, pktmbuf_pool[rte_socket_id()]);
					*left_mbuf = dproxy_http_split_requests(vm, conn, input_mbuf, offset);
#else
					/*netfe_pktmbuf_split can work, but it use copy front side memory,
					 *which make uri_start and method pointer in my_ngx_http_request_s invalid, we can print or get the
					 *request line info in http_parse_request_or_response where just request line parsed finished if
					 * we want to usenetfe_pktmbuf_split(but memory copy should effect performance)
					 */
					struct rte_mbuf *tmp_mbuf;
					uint32_t offset = processed_data_end_position - vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
					tmp_mbuf = netfe_pktmbuf_split(&input_mbuf, offset, pktmbuf_pool[rte_socket_id()]);
					*left_mbuf = input_mbuf;
					//input_mbuf = tmp_mbuf;
					conn->cons_side->parsing_req_mb = tmp_mbuf;
#endif
				}
				htp_req_debug_print("%s: msg with body finished, remained mbuf: %p\n", __FUNCTION__, *left_mbuf);

				//dproxy_http_headers_check_helper(conn);
				return EHTTP_CUR_INPUT_PARSED_A_REQ_RES;
			case EHTTP_HEADER_LINE_PARSE_COMPLETED:
				/*one request header is OK*/
				//dproxy_http_header_check_helper(conn);
				//ngx_http_modsecurity_load_headers_in(conn);
				//dproxy_http_reqeust_run_phases(conn, SHTTP_REQ_WAITING_REQHEADER);
				dproxy_http_parse_set_next_parse_data_position(vm, processed_data_end_position, &input_mbuf, &cur_buff, &cur_buff_len, parse_data);
				continue;
			case EHTTP_HEADER_DONE_PARSE_COMPLETED:
				/*parse header done and content-length > 0*/
				dproxy_http_parse_set_next_parse_data_position(vm, processed_data_end_position, &input_mbuf, &cur_buff, &cur_buff_len, parse_data);
				continue;
			case EHTTP_REQUEST_LINE_PARSE_COMPLETED:
				/*request line parse OK*/
				//dproxy_http_reqeust_run_phases(conn, SHTTP_REQ_WAITING_REQLINE);
				dproxy_http_parse_set_next_parse_data_position(vm, processed_data_end_position, &input_mbuf, &cur_buff, &cur_buff_len, parse_data);
				continue;
			case EHTTP_MESSAGE_PARSE_CONTINUE:
				/*reqeust line or header or body in-completed, ngixn parse want more data*/
				{
					parse_data->last_parsed_mbuf = input_mbuf;
					//input_mbuf = input_mbuf->next;
					input_mbuf = vlib_get_next_buffer(vm, input_mbuf);
					if (input_mbuf == NULL) {
						htp_req_debug_print("%s: mbuf %p parse to end, no next mbuf\n", __FUNCTION__, parse_data->last_parsed_mbuf );
						cur_buff = NULL;
						cur_buff_len = 0;
					} else {
						htp_req_debug_print("%s: mbuf %p parse to end, read next mbuf %p.\n", __FUNCTION__, parse_data->last_parsed_mbuf, input_mbuf );
						cur_buff = vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
						//cur_buff_len = rte_pktmbuf_data_len(input_mbuf);
						cur_buff_len = input_mbuf->current_length;
					}
					continue;
				}
			default:
				htp_req_debug_print("%s: return value %d which unexpected!!!!!!\n", __FUNCTION__, ret);
				return EHTTP_CUR_INPUT_MESSAGE_PARSE_ERROR;
		}
	}
	return EHTTP_CUR_INPUT_MESSAGE_PARSE_INCOMPLETE;
}

static int dproxy_http_parse_response_message(vlib_main_t *vm, dproxy_http_upstream_t *upstream, vlib_buffer_t *input_mbuf, vlib_buffer_t **left_mbuf)
{
	unsigned char *cur_buff = NULL;
	int cur_buff_len = 0;
	//http_parse_data_t *parse_data = conn->cons_side;

	*left_mbuf = input_mbuf;
	//skip leading empty mbuf;
	while (input_mbuf != NULL && input_mbuf->current_length == 0) {
		//input_mbuf	= input_mbuf->next;
		input_mbuf = vlib_get_next_buffer(vm, input_mbuf);
	}

	if (upstream->last_parsed_mbuf) {
		//input_mbuf = upstream->last_parsed_mbuf->next;
		input_mbuf = vlib_get_next_buffer(vm, upstream->last_parsed_mbuf);
		if (input_mbuf == NULL) {
			htp_resp_debug_print("%s last_parsed_mbuf next is NULL return PARSE_INCOMPLETE\n", __func__);
			return EHTTP_CUR_INPUT_MESSAGE_PARSE_INCOMPLETE;
		} else {
			htp_resp_debug_print("%s input_mbuf start from last_parsed_mbuf next\n",__func__);
		}
	}

	if (input_mbuf == NULL) {
		htp_resp_debug_print("%s input_mbuf is empty return PARSE_ERROR\n", __func__);
		return EHTTP_CUR_INPUT_MESSAGE_PARSE_ERROR;
	}

	htp_resp_debug_print("%s:%d input_mbuf data_len %d, pkt_len %d\n", __func__, __LINE__, input_mbuf->current_length, vlib_buffer_length_in_chain(vm, input_mbuf));
	cur_buff = vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
	//cur_buff_len = rte_pktmbuf_data_len(input_mbuf);
	cur_buff_len = input_mbuf->current_length;
	while (cur_buff != NULL && cur_buff_len > 0) {
		int ret = 0;
		unsigned char *input_mbuf_list_firstp;
		unsigned char *processed_data_end_position = NULL;
		ret = http_parse_response(cur_buff, cur_buff_len, upstream, &processed_data_end_position);
		htp_resp_debug_print("%s:%d input_mbuf data_len %d, pkt_len %d\n", __func__, __LINE__, input_mbuf->current_length, vlib_buffer_length_in_chain(vm, input_mbuf));
		if(processed_data_end_position != NULL) {
			input_mbuf_list_firstp = vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
			//cur_buff_len = input_mbuf_list_firstp + rte_pktmbuf_data_len(input_mbuf) - processed_data_end_position;
			cur_buff_len = input_mbuf_list_firstp + input_mbuf->current_length - processed_data_end_position;
			htp_resp_debug_print("%s cur_buff_len %d\n", __func__, cur_buff_len);
		} else {
			cur_buff_len = 0;
			htp_resp_debug_print("%s cur_buff_len %d\n", __func__, cur_buff_len);
		}

		switch(ret) {
			case EHTTP_MESSAGE_PARSE_PARAM_ERROR:
			case EHTTP_MESSAGE_PARSE_ERROR:
				return EHTTP_CUR_INPUT_MESSAGE_PARSE_ERROR;
			case EHTTP_MESSAGE_PARSE_COMPLETED:
				/*It's body return, body had been parse complete*/
			case EHTTP_HEADER_DONE_NOBY_PARSE_COMPLETED:
				/*Ngx tell header parse done and content-len == 0*/
				htp_resp_debug_print("%s:%d input_mbuf data_len %d, pkt_len %d\n", __func__, __LINE__,
					input_mbuf->current_length, vlib_buffer_length_in_chain(vm, input_mbuf));
				//if((input_mbuf->next == NULL) && (cur_buff_len == 0)) {
				if(!(input_mbuf->flags & VLIB_BUFFER_NEXT_PRESENT) && (cur_buff_len == 0)) {
					*left_mbuf = NULL;
				} else if(cur_buff_len == 0) {
					//*left_mbuf = input_mbuf->next;
					*left_mbuf = vlib_get_next_buffer(vm, input_mbuf);
					//curth_myhttp_stats.dproxy_myhttp_stats_resp_trailer++;
					if(*left_mbuf) {
						//input_mbuf->next = NULL;
						input_mbuf->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
					}
				} else {
					//curth_myhttp_stats.dproxy_myhttp_stats_resp_trailer++;
#if 1
					htp_resp_debug_print("%s:%d input_mbuf data_len %d, pkt_len %d\n", __func__, __LINE__,
						input_mbuf->current_length, vlib_buffer_length_in_chain(vm, input_mbuf));
					uint32_t offset = processed_data_end_position - vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
					//*left_mbuf = m_split(input_mbuf, offset, pktmbuf_pool[rte_socket_id()]);
					*left_mbuf = dproxy_http_split_responses(vm, upstream, input_mbuf, offset);
#else
					/*netfe_pktmbuf_split can work, but it use copy front side memory,
					 *which make uri_start and method pointer in my_ngx_http_request_s invalid, we can print or get the
					 *request line info in http_parse_request_or_response where just request line parsed finished if
					 * we want to usenetfe_pktmbuf_split(but memory copy should effect performance)
					 */
					struct rte_mbuf *tmp_mbuf;
					uint32_t offset = processed_data_end_position - vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
					tmp_mbuf = netfe_pktmbuf_split(&input_mbuf, offset, pktmbuf_pool[rte_socket_id()]);
					*left_mbuf = input_mbuf;
					//input_mbuf = tmp_mbuf;
					conn->cons_side->parsing_req_mb = tmp_mbuf;
#endif
				}
				htp_resp_debug_print("%s: msg with body finished, remained mbuf: %p\n", __FUNCTION__, *left_mbuf);

				//dproxy_http_headers_check_helper(conn);
				return EHTTP_CUR_INPUT_PARSED_A_REQ_RES;
			case EHTTP_HEADER_LINE_PARSE_COMPLETED:
				/*one request header is OK*/
				//dproxy_http_header_check_helper(conn);
				//ngx_http_modsecurity_load_headers_in(conn);
				//dproxy_http_reqeust_run_phases(conn, SHTTP_REQ_WAITING_REQHEADER);
				dproxy_http_parse_set_next_parse_resp_position(vm, processed_data_end_position, &input_mbuf, &cur_buff, &cur_buff_len, upstream);
				continue;
			case EHTTP_HEADER_DONE_PARSE_COMPLETED:
				/*parse header done and content-length > 0*/
				dproxy_http_parse_set_next_parse_resp_position(vm, processed_data_end_position, &input_mbuf, &cur_buff, &cur_buff_len, upstream);
				continue;
			case EHTTP_REQUEST_LINE_PARSE_COMPLETED:
				/*request line parse OK*/
				//dproxy_http_reqeust_run_phases(conn, SHTTP_REQ_WAITING_REQLINE);
				dproxy_http_parse_set_next_parse_resp_position(vm, processed_data_end_position, &input_mbuf, &cur_buff, &cur_buff_len, upstream);
				continue;
			case EHTTP_MESSAGE_PARSE_CONTINUE:
				/*reqeust line or header or body in-completed, ngixn parse want more data*/
				{
					upstream->last_parsed_mbuf = input_mbuf;
					//input_mbuf = input_mbuf->next;
					input_mbuf = vlib_get_next_buffer(vm, input_mbuf);
					if (input_mbuf == NULL) {
						htp_resp_debug_print("%s: mbuf %p parse to end, no next mbuf\n", __FUNCTION__, upstream->last_parsed_mbuf );
						cur_buff = NULL;
						cur_buff_len = 0;
					} else {
						htp_resp_debug_print("%s: mbuf %p parse to end, read next mbuf %p.\n", __FUNCTION__, upstream->last_parsed_mbuf, input_mbuf );
						cur_buff = vlib_buffer_hili_mtod(input_mbuf, unsigned char *);
						//cur_buff_len = rte_pktmbuf_data_len(input_mbuf);
						cur_buff_len = input_mbuf->current_length;
					}
					continue;
				}
			default:
				htp_resp_debug_print("%s: return value %d which unexpected!!!!!!\n", __FUNCTION__, ret);
				return EHTTP_CUR_INPUT_MESSAGE_PARSE_ERROR;
		}
	}
	return EHTTP_CUR_INPUT_MESSAGE_PARSE_INCOMPLETE;
}

int dproxy_http_input_empty(vlib_main_t *vm, session_t *conn)
{
	int len = 0;
	vlib_buffer_t *mbuf;
	/*have process TCP FIN, don't (and should no data come after FIN) handle any things*/
	len = hili_session_read(vm, conn, &mbuf);
	if (len > 0) {
		vlib_buffer_hili_free_one_buffer(vm, mbuf);
	}
	return EHTTP_OK;
}

static int dproxy_http_cleanup(http_parse_data_t *http_data)
{
	FUNC_TRACE;
	vlib_main_t *vm;
	if (http_data == NULL) {
		htp_req_debug_print("%s conn->http_data is NULL\n", __func__);
		return;
	}

	vm = vlib_get_main();

	if (http_data->next_request) {
		if (http_data->parsing_req_mb && http_data->parsing_req_mb != http_data->next_request) {
			//dproxy_mbuf_free_memtrace(conn->http_data->parsing_req_mb);
			vlib_buffer_hili_free_one_buffer(vm, http_data->parsing_req_mb);
			http_data->parsing_req_mb = NULL;
		}
		//dproxy_mbuf_free_memtrace(conn->http_data->next_request);
		vlib_buffer_hili_free_one_buffer(vm, http_data->next_request);
		http_data->next_request = NULL;
		htp_req_debug_print("%s Free http_data->next_request\n", __func__);
	}

	if (http_data->req_handled > 1) {
		//curth_myhttp_stats.dproxy_myhttp_stats_mulreq_con++;
	}

	if (http_data->upstream) {
		dproxy_http_upstream_t *dp_upstream;
		dp_upstream = http_data->upstream;
		if (dp_upstream->parsing_resp_mb && dp_upstream->parsing_resp_mb != dp_upstream->resp_next_mb) {
			//dproxy_mbuf_free_memtrace(dp_upstream->parsing_resp_mb);
			vlib_buffer_hili_free_one_buffer(vm, dp_upstream->parsing_resp_mb);
			dp_upstream->parsing_resp_mb = NULL;
		}
		if (dp_upstream->resp_next_mb) {
			//dproxy_mbuf_free_memtrace(dp_upstream->resp_next_mb);
			vlib_buffer_hili_free_one_buffer(vm, dp_upstream->resp_next_mb);
			dp_upstream->resp_next_mb = NULL;
		}

		//dproxy_http_req_upstream_free(dp_upstream);
		proxy_http_upstream_free(dp_upstream);
		http_data->upstream = NULL;
	}

	if (http_data->req.upstream) {
		//ngx_http_req_upstream_free(conn->http_data->req.upstream);
		ngx_http_upstream_free(http_data->req.upstream);
		http_data->req.upstream = NULL;
	}

	//dproxy_http_parse_data_free(conn->http_data);
	http_data_free(http_data);
	//conn->http_data = NULL;
	return EHTTP_OK;
}


//reset can triggered by RST pkt or http layer error
static void dproxy_http_reset(http_parse_data_t *http_data)
{
	FUNC_TRACE;
	uint16_t rst_code = RST_ID_FROM_HTTP_3;

	if (http_data->rst_code != 0) {
		rst_code = http_data->rst_code;
	}

	if (http_data->pipe) {
		hili_session_terminate(http_data->pipe, rst_code);
	}
	http_data->reqcon = NULL;
	http_data->pipe = NULL;

	//New added by vpp base http proxy
	dproxy_http_cleanup(http_data);
}

int dproxy_http_request_handler(session_t *conn)
{
	int cb_ret;
	http_parse_data_t *http_data = conn->http_data;
	if (hili_session_is_reset(conn)) {
		//if it's called by tcp stack, the rx_rst will delete the conn, so here just tell other side
		htp_req_debug_print("%s connection is reseted\n", __func__);
		dproxy_http_reset(http_data);
		//dproxy_http_parse_data_free(http_data);
		conn->rx_cb_func = NULL;
		return EHTTP_MBUF_NO_USE;
	}

	if (conn->write) {
		/* write event handler is dproxy_http_request_empty_handler*/
		cb_ret = http_data->write_event_handler(http_data);/*Now no data send from here(assume pipe_input perfect work), but as normal,
					we should give pkt to TCP here other than pipe_input, because here we can control the pkt
					work with send wind of TCP, TODO*/
		conn->write = 0;
	} else {
		if ((hili_session_current_status(conn) == HILI_SESSION_CUR_CLOSING) &&
				!(http_data->flags & HTTP_FLAG_HANDLE_TCP_FIN)) {
				http_data->flags |= HTTP_FLAG_HANDLE_TCP_FIN;
				if (http_data->flags & HTTP_FLAG_ACTIVE_CLOSE) {
					//curth_myhttp_stats.dproxy_myhttp_stats_req_act_close++;
					dproxy_http_close(http_data);
				} else {
					http_data->flags |= HTTP_FLAG_PASSIVE_CLOSE;
					//curth_myhttp_stats.dproxy_myhttp_stats_req_pasv_close++;
					hili_session_halfclose(http_data->pipe);
				}
				return EHTTP_MBUF_NO_USE;
		} else {
			cb_ret = http_data->read_event_handler(http_data);/*dproxy_http_block_reading*/
		}
		conn->read = 0;
	}

	if (conn->rx_cb_func && hili_session_is_leaving(conn)) {
		//TODO caogw
		htp_req_debug_print("%s http request side is leaving\n", __func__);
		//dproxy_http_parse_data_free(cons_side);
		conn->rx_cb_func = NULL;
	}

	return cb_ret;
}

/*request read callback*/
static int dproxy_http_block_reading(http_parse_data_t *http_data)
{
	FUNC_TRACE;
	/*data maybe in recvq_head, so we just tell caller, mbuf used, so caller do nothing*/
	return EHTTP_MBUF_USED;
}

/*request write callback*/
static int dproxy_http_request_empty_handler(http_parse_data_t *http_data)
{
	FUNC_TRACE;
	return EHTTP_MBUF_USED;
}

static void dproxy_http_reset_upstream_parse_data(vlib_main_t *vm, dproxy_http_upstream_t *upstream)
{
	if (upstream->parsing_resp_mb) {
		//dproxy_mbuf_free_memtrace(upstream->parsing_resp_mb);
		vlib_buffer_hili_free_one_buffer(vm, upstream->parsing_resp_mb);
		upstream->parsing_resp_mb = NULL;
	}
	upstream->last_parsed_mbuf = NULL;

	/*reset some field for new coming request*/
	upstream->current_parse_state = PARSE_STATE_RESP_START;
	upstream->content_length = 0;
	//upstream->current_body_length = 0;
	upstream->is_chunked = 0;
	upstream->content_length_exists = 0;
	//dproxy_http_reset_requqest(&parse_data->req);
}


/*upstream read callback， alias for dproxy_http_upstream_input*/
static void dproxy_http_upstream_process_header(vlib_main_t *vm, dproxy_http_upstream_t *upstream)
{
	FUNC_TRACE;
	int len;
	//int ret;
	int parse_result;
	vlib_buffer_t *mbuf;
	http_parse_data_t *http_data;
	session_t *conn;

	http_data = upstream->http_data;
	conn = http_data->pipe;
	len = hili_session_read(vm, conn, &mbuf);
	if (len > 0) {
		//dproxy_mbuf_set_alloc_id_all(mbuf, DPROXY_MBUF_ALLOC_ID_HTTP_3);
		if (upstream->parsing_resp_mb == NULL) {
			htp_ups_debug_print("%s The new response coming in, let's record the buffer\n", __func__);
			upstream->current_parse_state = PARSE_STATE_RESP_START;
			upstream->parsing_resp_mb = mbuf;
			htp_ups_debug_print("%s parsing_resp_mb data_len %d, pkt_len %d\n", __func__, 
					upstream->parsing_resp_mb->current_length, vlib_buffer_length_in_chain(vm, upstream->parsing_resp_mb));
		}

		/*EHTTP_CUR_INPUT_MESSAGE_PARSE_INCOMPLETE will make next_request not NULL*/
		if (upstream->resp_next_mb == NULL) {
			htp_ups_debug_print("%s upstream->resp_next_mb  is NULL, use this mbuf as first\n", __func__);
			upstream->resp_next_mb = mbuf;
			htp_ups_debug_print("%s resp_next_mb data_len %d, pkt_len %d\n", __func__, 
					upstream->resp_next_mb->current_length, vlib_buffer_length_in_chain(vm, upstream->resp_next_mb));
		} else {
			vlib_buffer_hili_chain(vm, upstream->resp_next_mb , mbuf);
			htp_ups_debug_print("%s resp_next_mb data_len %d, pkt_len %d\n", __func__, 
					upstream->resp_next_mb->current_length, vlib_buffer_length_in_chain(vm, upstream->resp_next_mb));
		}

		while (upstream->resp_next_mb != NULL) {
			vlib_buffer_t *remain = NULL;
			parse_result = dproxy_http_parse_response_message(vm, upstream, upstream->resp_next_mb, &remain);
			upstream->resp_next_mb = remain;
			htp_ups_debug_print("%s resp_next_mb data_len %d, pkt_len %d\n", __func__, 
					upstream->resp_next_mb->current_length, vlib_buffer_length_in_chain(vm, upstream->resp_next_mb));
			if(EHTTP_CUR_INPUT_MESSAGE_PARSE_INCOMPLETE == parse_result) {
				if (hili_session_is_leaving(conn)) {
					//curth_myhttp_stats.dproxy_myhttp_stats_resp_invalid++;
					htp_ups_debug_print("%s Seem FIN coming in but still not complete, bad request!\n", __func__);
					return;
				}
				//curth_myhttp_stats.dproxy_myhttp_stats_resp_incomp++;
				htp_ups_debug_print("%s There is no more mbuf to be used to parse the whole req_line/header/body, so break\n", __func__);
				break;
			} else if (parse_result < 0) {
				//curth_myhttp_stats.dproxy_myhttp_stats_resp_invalid++;
				//dproxy_tcp_parser_conn_shutdown(conn);
				return;
			} else if (EHTTP_CUR_INPUT_PARSED_A_REQ_RES == parse_result) {
				if (dproxy_http_upstream_process_headers(&upstream->http_data->req, upstream->http_data->req.upstream) != NGX_OK) {
					htp_ups_debug_print("%s dproxy_http_upstream_process_headers return not OK\n", __func__);
					//curth_myhttp_stats.dproxy_myhttp_stats_ups_hdr_fail++;
					return;
				} else {//headers done, start to send response
					htp_ups_debug_print("%s start to call dproxy_http_upstream_send_responsen\n", __func__);
					dproxy_http_upstream_send_response(vm, upstream);
					dproxy_http_reset_upstream_parse_data(vm, upstream);
					if (upstream->resp_next_mb != NULL) {
						upstream->parsing_resp_mb = upstream->resp_next_mb;
					}
					//continue to process next mbuf ?
					return;
				}
			} else {
				//curth_myhttp_stats.dproxy_myhttp_stats_resp_unexp++;
				htp_ups_debug_print("%s !!!!!!Something unknow happend !!!!!!!!\n", __func__);
			}
		}
	}else {
		//curth_myhttp_stats.dproxy_myhttp_stats_resp_read_err++;
		htp_ups_debug_print("%s !!!!!!hili_session_read <=0 !!!!!!!!\n", __func__);
	}
	//return;
}

static void dproxy_http_upstream_send_response(vlib_main_t *vm, dproxy_http_upstream_t *upstream)
{
	FUNC_TRACE;
	ngx_int_t rc;
	ngx_http_request_t *r;
	ngx_http_upstream_t *u;
	vlib_buffer_t *send_header = NULL;
	session_t *conn;
	uint32_t body_length = 0;
	conn = upstream->http_data->reqcon;

	if (conn == NULL) {
		htp_ups_debug_print("request connection is NULL\n");
		return;
	}

	r = &upstream->http_data->req;
	u = r->upstream;
	rc = dproxy_http_send_header(r, &send_header);
	if (send_header == NULL) {
		htp_ups_debug_print("dproxy_http_send_header failed, maybe it's short memory\n");
		return;
	}
	DEBUG_DUMP_SESSION_VLIB_BUFFER("header to client side", send_header);
	DEBUG_DUMP_SESSION_VLIB_BUFFER("body which split from response", upstream->resp_next_mb);
	if (rc == NGX_OK) {
		if (upstream->resp_next_mb) {
			//body_length = upstream->resp_next_mb->pkt_len;
			body_length = vlib_buffer_length_in_chain(vm, upstream->resp_next_mb);
			htp_ups_debug_print("%s:%d current body length %d \n", __func__, __LINE__, body_length);
#if 0
			if (rte_pktmbuf_chain(send_header, upstream->resp_next_mb) != 0) {
				curth_myhttp_stats.dproxy_myhttp_stats_chain_resbd_fail++;
				RTE_LOG(ERR, HTTP, "%s:%d rte_pktmbuf_chain failed\n", __func__, __LINE__);
				return;
			}
#endif
			vlib_buffer_hili_chain(vm, send_header , upstream->resp_next_mb);
			/* TODO, if the response without body (HEAD request etc)*/
			upstream->current_body_length = body_length;
			upstream->resp_next_mb = NULL;
		}
		DEBUG_DUMP_SESSION_VLIB_BUFFER("header and body chain togetehr", send_header);
		if (hili_session_write(vm, conn, send_header, vlib_buffer_length_in_chain(vm, send_header)) < 0) {
			//curth_myhttp_stats.dproxy_myhttp_stats_ups_send_hdr_fail++;
			htp_ups_debug_print("Failed to call hili_session_write\n");
			return;
		}
	}

	if (rc == NGX_ERROR || rc > NGX_OK || r->post_action) {
		htp_ups_debug_print("rc == NGX_ERROR || rc > NGX_OK || r->post_action\n");
		dproxy_http_upstream_finalize_request(r, u, rc);
		return;
	}
	u->header_sent = 1;
	upstream->http_data->header_sent = 1;
}

static ngx_int_t dproxy_http_send_header(ngx_http_request_t *r, vlib_buffer_t **mbuf)
{
	FUNC_TRACE;
	return dproxy_http_header_filter(r, mbuf);
}

#define dproxy_append_data_to_mbuf(cp, cp_start, data, len) do {\
		if ((((cp) - (cp_start)) + (len)) > ONE_SEGMENT_MAX_LEN) { \
			htp_req_debug_print("no room in mbuf for appeding data which length is %d\n", (len)); \
			return NGX_ERROR; \
		} \
		clib_memcpy_fast((cp), (data), (len)); \
		(cp) += (len); \
	} while (0)

/*copy from ngx_sprintf_num and first copy for content_length*/
static ngx_int_t dproxy_sprintf_num(uint8_t *cp, uint8_t *start_cp, uint64_t ui64)
{
	u_char		   *p, temp[NGX_INT64_LEN + 1];
					   /*
						* we need temp[NGX_INT64_LEN] only,
						* but icc issues the warning
						*/
	size_t			len;
	uint32_t		ui32;

	//static u_char   hex[] = "0123456789abcdef";
	p = temp + NGX_INT64_LEN;

	if (ui64 <= (uint64_t) NGX_MAX_UINT32_VALUE) {

		/*
		 * To divide 64-bit numbers and to find remainders
		 * on the x86 platform gcc and icc call the libc functions
		 * [u]divdi3() and [u]moddi3(), they call another function
		 * in its turn.  On FreeBSD it is the qdivrem() function,
		 * its source code is about 170 lines of the code.
		 * The glibc counterpart is about 150 lines of the code.
		 *
		 * For 32-bit numbers and some divisors gcc and icc use
		 * a inlined multiplication and shifts.  For example,
		 * unsigned "i32 / 10" is compiled to
		 *
		 *	   (i32 * 0xCCCCCCCD) >> 35
		 */

		ui32 = (uint32_t) ui64;

		do {
			*--p = (u_char) (ui32 % 10 + '0');
		} while (ui32 /= 10);

	} else {
		do {
			*--p = (u_char) (ui64 % 10 + '0');
		} while (ui64 /= 10);
	}

	len = (temp + NGX_INT64_LEN) - p;

	dproxy_append_data_to_mbuf(cp, start_cp, p, len);
	return len;
}

static ngx_int_t dproxy_http_header_filter(ngx_http_request_t *r, vlib_buffer_t **header_mb)
{
	FUNC_TRACE;
	vlib_buffer_t *outmb = NULL;
	size_t len;
	uint8_t *cp, *start_cp, *tmpp;
	ngx_str_t *status_line;
	ngx_uint_t  status, i;
	ngx_list_part_t *part;
	ngx_table_elt_t *header;

	if (r->header_sent) {
		LINE_TRACE;
		return NGX_OK;
	}

	r->header_sent = 1;
	if (r != r->main) {
		LINE_TRACE;
		return NGX_OK;
	}
#if 0
	if (r->http_version < NGX_HTTP_VERSION_10) {
	}
#endif
	if (r->method == NGX_HTTP_HEAD) {
		r->header_only = 1;
	}

	if (r->headers_out.last_modified_time != -1) {
		if (r->headers_out.status != NGX_HTTP_OK
			&& r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
			&& r->headers_out.status != NGX_HTTP_NOT_MODIFIED)
		{
			r->headers_out.last_modified_time = -1;
			r->headers_out.last_modified = NULL;
		}
	}

	outmb = hili_create_one_mbuf(0, VLIB_BUFFER_ALLOC_ID_HTTP_402);
	if (outmb == NULL) {
		LINE_TRACE;
		return NGX_ERROR;
	}

	cp = start_cp = vlib_buffer_hili_mtod(outmb, uint8_t *);

	len = sizeof("HTTP/1.x ") - 1 + sizeof(CRLF) - 1
		/* the end of the header */
		+ sizeof(CRLF) - 1;

	dproxy_append_data_to_mbuf(cp, start_cp, "HTTP/1.1 ", sizeof("HTTP/1.x ") - 1);
    /* status line */
    /*when parse_status_line in func http_parse_response u->header_in.status_line.len set to 0*/
	if (r->headers_out.status_line.len) {
		len += r->headers_out.status_line.len;
		status_line = &r->headers_out.status_line;
		status = 0;
	} else {
        htp_req_debug_print("Come here r->headers_out.status_line.len is 0!!\n");
		status = r->headers_out.status;
		if (status >= NGX_HTTP_OK && status < NGX_HTTP_LAST_2XX) {
			/* 2XX */
			if (status == NGX_HTTP_NO_CONTENT) {
				r->header_only = 1;
				ngx_str_null(&r->headers_out.content_type);
				r->headers_out.last_modified_time = -1;
				r->headers_out.last_modified = NULL;
				r->headers_out.content_length = NULL;
				r->headers_out.content_length_n = -1;
			}

			status -= NGX_HTTP_OK;
			status_line = &dproxy_http_status_lines[status];
			len += dproxy_http_status_lines[status].len;
		} else if (status >= NGX_HTTP_MOVED_PERMANENTLY && status < NGX_HTTP_LAST_3XX) {
			/* 3XX */

			if (status == NGX_HTTP_NOT_MODIFIED) {
				r->header_only = 1;
			}

			status = status - NGX_HTTP_MOVED_PERMANENTLY + NGX_HTTP_OFF_3XX;
			status_line = &dproxy_http_status_lines[status];
			len += dproxy_http_status_lines[status].len;
		} else if (status >= NGX_HTTP_BAD_REQUEST && status < NGX_HTTP_LAST_4XX) {
			/* 4XX */
			status = status - NGX_HTTP_BAD_REQUEST
							+ NGX_HTTP_OFF_4XX;

			status_line = &dproxy_http_status_lines[status];
			len += dproxy_http_status_lines[status].len;
		} else if (status >= NGX_HTTP_INTERNAL_SERVER_ERROR && status < NGX_HTTP_LAST_5XX) {
			/* 5XX */
			status = status - NGX_HTTP_INTERNAL_SERVER_ERROR
							+ NGX_HTTP_OFF_5XX;

			status_line = &dproxy_http_status_lines[status];
			len += dproxy_http_status_lines[status].len;
		} else {
			len += NGX_INT_T_LEN + 1 /* SP */;
			status_line = NULL;
		}

		if (status_line && status_line->len == 0) {
			status = r->headers_out.status;
			len += NGX_INT_T_LEN + 1 /* SP */;
			status_line = NULL;
			//TODO suport this case and remove following two line codes
			htp_req_debug_print("status_line->len is 0, don't support this case\n");
			return NGX_ERROR;
		}
	}

	if (status_line) {
		dproxy_append_data_to_mbuf(cp, start_cp, status_line->data, status_line->len);
	} else {
		//TODO suport only status case;
		htp_req_debug_print("TODO suport only status case\n");
	}

	*cp++ = CR;
	*cp++ = LF;

	len += sizeof(dproxy_http_server_full_string) - 1;

	dproxy_append_data_to_mbuf(cp, start_cp, dproxy_http_server_full_string, (sizeof(dproxy_http_server_full_string) - 1));

	if (r->headers_out.date == NULL) {
		len += sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
		htp_req_debug_print("TODO use the current time\n");
		dproxy_append_data_to_mbuf(cp, start_cp, ("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF),
				(sizeof("Date: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1));
	}

    if (r->headers_out.content_type.len) {
        len += sizeof("Content-Type: ") - 1
               + r->headers_out.content_type.len + 2;/*Content-Type: application/json CRLF (so +2 is for CRLF)*/
		tmpp = cp;
		dproxy_append_data_to_mbuf(cp, start_cp, "Content-Type: ", sizeof("Content-Type: ") - 1);
		dproxy_append_data_to_mbuf(cp, start_cp, r->headers_out.content_type.data, r->headers_out.content_type.len);
		/*if charset exist, then Content-Type: application/json; charset=xxx CRLF*/
		if (r->headers_out.content_type_len == r->headers_out.content_type.len
			&& r->headers_out.charset.len) {
			len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
			dproxy_append_data_to_mbuf(cp, start_cp, "; charset=", sizeof("; charset=") - 1);
			dproxy_append_data_to_mbuf(cp, start_cp, r->headers_out.charset.data, r->headers_out.charset.len);
			/* update r->headers_out.content_type for possible logging */
			r->headers_out.content_type.len = cp - tmpp;
			r->headers_out.content_type.data = tmpp;
		}
		*cp++ = CR;
		*cp++ = LF;
    }

	if (r->headers_out.content_length == NULL
		&& r->headers_out.content_length_n >= 0)
	{
		int tmp_len;
		len += sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + 2;
		dproxy_append_data_to_mbuf(cp, start_cp, ("Content-Length: "), sizeof("Content-Length: ") - 1);
		/*in dproxy_sprintf_num use dproxy_append_data_to_mbuf can append data but coun't increase cp*/
		tmp_len = dproxy_sprintf_num(cp, start_cp, r->headers_out.content_length_n);
		cp += tmp_len;
		*cp++ = CR;
		*cp++ = LF;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1;
		htp_req_debug_print("TODO support Last-Modified real time\n");
		dproxy_append_data_to_mbuf(cp, start_cp, ("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF),
					sizeof("Last-Modified: Mon, 28 Sep 1970 06:00:00 GMT" CRLF) - 1);
    }

	// TODO redirect support

	if (r->chunked) {
		len += sizeof("Transfer-Encoding: chunked" CRLF) - 1;
		dproxy_append_data_to_mbuf(cp, start_cp, "Transfer-Encoding: chunked" CRLF, sizeof("Transfer-Encoding: chunked" CRLF) - 1);
	}

	if (r->headers_out.status == NGX_HTTP_SWITCHING_PROTOCOLS) {
		len += sizeof("Connection: upgrade" CRLF) - 1;
		dproxy_append_data_to_mbuf(cp, start_cp, ("Connection: upgrade" CRLF), sizeof("Connection: upgrade" CRLF) - 1);
	} else if (r->keepalive) {
		len += sizeof("Connection: keep-alive" CRLF) - 1;
		dproxy_append_data_to_mbuf(cp, start_cp, ("Connection: keep-alive" CRLF), sizeof("Connection: keep-alive" CRLF) - 1);
	} else {
		len += sizeof("Connection: close" CRLF) - 1;
		dproxy_append_data_to_mbuf(cp, start_cp, ("Connection: close" CRLF), sizeof("Connection: close" CRLF) - 1);
	}

	// TODO gzip support

	part = &r->headers_out.headers.part;
	header = part->elts;

	for (i = 0; /* void */; i++) {

	    if (i >= part->nelts) {
	        if (part->next == NULL) {
	            break;
	        }

	        part = part->next;
	        header = part->elts;
	        i = 0;
	    }

	    if (header[i].hash == 0) {
	        continue;
	    }

	    len += header[i].key.len + sizeof(": ") - 1 + header[i].value.len + sizeof(CRLF) - 1;
		dproxy_append_data_to_mbuf(cp, start_cp, header[i].key.data, header[i].key.len);
		*cp++ = ':';
		*cp++ = ' ';
		dproxy_append_data_to_mbuf(cp, start_cp, header[i].value.data, header[i].value.len);
		*cp++ = CR;
		*cp++ = LF;
	}

	*cp++ = CR;
	*cp++ = LF;

	r->header_size = cp - start_cp;

	//outmb->pkt_len = outmb->data_len = (cp - start_cp);
	outmb->current_length = (cp - start_cp);//one buffer without next, so pkt_len no need to set, will be set when check or chain
	if (r->header_size > outmb->current_length) {
		htp_req_debug_print("r->header_size (%d) > outmb->current_length (%d)\n", r->header_size, outmb->current_length);
		return NGX_ERROR;
	}
	LINE_TRACE;
	*header_mb = outmb;
	return NGX_OK;
	//return dproxy_http_write_filter(r, outmb);
}
#if 0
static ngx_int_t dproxy_http_write_filter(ngx_http_request_t *r, struct rte_mbuf *in)
{
	FUNC_TRACE;
    if (hili_session_write(hili_ss->cons_side, , len) < 0) {
    }
	return NGX_OK;
}
#endif

static ngx_int_t
ngx_http_upstream_copy_header_line_tai2(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  *ho, **ph;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
    }

    return NGX_OK;
}

extern ngx_hash_t upstream_headers_in_hash;
static ngx_int_t
dproxy_http_upstream_process_headers(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
	ngx_uint_t                      i;
	ngx_list_part_t                *part;
	ngx_table_elt_t                *h;
	ngx_http_upstream_header_t     *hh;
	//first X-Accel-Redirect
	//second copy u->headers_in.headers to r->headers_out.headers and check hide_header in this stage

	part = &u->headers_in.headers.part;
	h = part->elts;

	for (i = 0; /* void */; i++) {

		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			h = part->elts;
			i = 0;
		}

		hh = ngx_hash_find(&upstream_headers_in_hash, h[i].hash,
		h[i].lowcase_key, h[i].key.len);

		if (hh) {
			if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
				dproxy_http_upstream_finalize_request(r, u,
					NGX_HTTP_INTERNAL_SERVER_ERROR);
				return NGX_DONE;
			}

			continue;
		}

		if (ngx_http_upstream_copy_header_line_tai2(r, &h[i], 0) != NGX_OK) {
			dproxy_http_upstream_finalize_request(r, u,
				NGX_HTTP_INTERNAL_SERVER_ERROR);
			return NGX_DONE;
		}
	}

	//copy status line

	if (r->headers_out.server && r->headers_out.server->value.data == NULL) {
		r->headers_out.server->hash = 0;
	}

	if (r->headers_out.date && r->headers_out.date->value.data == NULL) {
		r->headers_out.date->hash = 0;
	}

	r->headers_out.status = u->headers_in.status_n;
	r->headers_out.status_line = u->headers_in.status_line;

	r->headers_out.content_length_n = u->headers_in.content_length_n;

	r->disable_not_modified = !u->cacheable;

	u->keepalive = !u->headers_in.connection_close;

	u->length = -1;

	return NGX_OK;
}


static char  ngx_http_proxy_version[] = " HTTP/1.0" CRLF;
static void dproxy_http_upstream_prepare_request(http_parse_data_t * http_data, vlib_buffer_t **outmb)
{
#if 0
	//Do the work like ngx_http_proxy_create_request, caculate the totoal length
	size_t loc_len, uri_len, len, body_len;
	ngx_http_request_t *r;
	uintptr_t                     escape;
	ngx_str_t                     method;

/* HTTPPROXY TODO should get the location.len from configuration.
	loc_len = (r->valid_location && ctx->vars.uri.len) ?
				  plcf->location.len : 0;  //当前location的名字 location xxx {} 中的xxx的长度3
*/
	loc_len = 0;

	r = &upstream->cons_side->req;
	method = r->method_name;
	method.len++;

	if (r->quoted_uri || r->space_in_uri || r->internal) {
		escape = 2 * ngx_escape_uri(NULL, r->uri.data + loc_len,
									r->uri.len - loc_len, NGX_ESCAPE_URI);
	}

	uri_len = r->uri.len - loc_len + escape
			  + sizeof("?") - 1 + r->args.len; //注意sizeof("?")是2字节

	if (uri_len == 0) {
		RTE_LOG(ERR, HTTP, "%s uri_len is 0\n", __func__);
		return;
	}

	len = method.len + sizeof(ngx_http_proxy_version) - 1 + sizeof(CRLF) - 1 + uri_len;

	body_len = 0;
	len += body_len;
	RTE_LOG(ERR, HTTP, "%s totoal length %d\n", __func__, len);

#endif

	/*start construct http request*/

	FUNC_TRACE;
	vlib_buffer_t *mp;
	uint8_t *cp, *start_cp;
	ngx_list_part_t *part;
	ngx_table_elt_t *header;
	int i;
	ngx_http_request_t *r = &http_data->req;
#if 0
	uint16_t state = upstream->peer->state;
	if (state != TCP_ST_ESTABLISHED && state != TCP_ST_CLOSE_WAIT) {
		RTE_LOG(ERR, HTTP, "%s current connection don't established wait it done\n", __func__);
		return;
	}
	RTE_LOG(ERR, HTTP, "%s tcp handshake finished, so let's go!!!\n", __func__);
#endif
	mp = hili_create_one_mbuf(0, VLIB_BUFFER_ALLOC_ID_HTTP_403);
	if (!mp) {
		*outmb = NULL;
		return;
	}
	start_cp = cp  = vlib_buffer_hili_mtod(mp, uint8_t *);

	/*method*/
	clib_memcpy_fast(cp, r->method_name.data, r->method_name.len);
	cp += r->method_name.len;
	*cp++ = ' ';

	/*uri*/
	clib_memcpy_fast(cp, r->unparsed_uri.data, r->unparsed_uri.len);
	cp += r->unparsed_uri.len;

	/*version*/
	clib_memcpy_fast(cp, ngx_http_proxy_version, sizeof(ngx_http_proxy_version) - 1);
	cp += (sizeof(ngx_http_proxy_version)- 1);

	part = &r->headers_in.headers.part;
	header = part->elts;

	for(i = 0; i < part->nelts; i++) {
		clib_memcpy_fast(cp, header[i].key.data, header[i].key.len);
		cp += header[i].key.len;
		*cp++ = ':';
		*cp++ = ' ';
		clib_memcpy_fast(cp, header[i].value.data, header[i].value.len);
		cp += header[i].value.len;
		*cp++ = CR;
		*cp++ = LF;
	}

	/* add "\r\n" at the header end */
	*cp++ = CR;
	*cp++ = LF;

	// DPROXY TODO add body
	//mp->pkt_len = mp->data_len = cp - start_cp;
	mp->current_length = cp - start_cp;
	*outmb = mp;
	/*end construct http request*/
}

/*return 1 when pipe close event first come*/
static inline int
dproxy_http_pipe_fin_first_coming(http_parse_data_t *http_data)
{
	if (http_data->pipe && (hili_session_current_status(http_data->pipe) == HILI_SESSION_CUR_CLOSING) &&
		!(http_data->flags & HTTP_FLAG_HANDLED_PIPE_FIN)) {
		return 1;
	}

	return 0;
}

static int dproxy_http_close(http_parse_data_t *http_data)
{
	FUNC_TRACE;
	session_t *request_conn;
	if (http_data->pipe) {
		((session_t *)http_data->pipe)->rx_cb_func = NULL;
		hili_session_close(http_data->pipe);
		http_data->pipe = NULL;
	}

	if (http_data->reqcon) {
		request_conn = http_data->reqcon;
		request_conn->rx_cb_func = NULL;
		hili_session_close(request_conn);
		http_data->reqcon = NULL;
	}

	dproxy_http_cleanup(http_data);
	request_conn->http_data = NULL;
	return NGX_OK;
}
//The error means that http internal error or upstream side error
static int dproxy_http_error(http_parse_data_t *http_data)
{
	FUNC_TRACE;
	uint16_t rst_code = RST_ID_FROM_HTTP_6;
	session_t *conn;
	if (http_data->rst_code != 0) {
		rst_code = http_data->rst_code;
	}

	if (http_data->reqcon) {
		conn = http_data->reqcon;
		conn->reset_errorcode = rst_code;
		conn->rx_cb_func = NULL;
		hili_session_terminate(conn, rst_code);
		http_data->reqcon = NULL;
		//New added by vpp base http proxy
		conn->http_data = NULL;
	}

	dproxy_http_reset(http_data);
	return EHTTP_OK;
}

static int dproxy_http_pipe_input(session_t *conn)
{
	http_parse_data_t *http_data;
	vlib_buffer_t *mb;
	int32_t len;
	vlib_main_t *vm;
	http_data = (http_parse_data_t *)conn->cons_side;
	if (http_data == NULL) {
		DPROXY_HTTP_ERROR(http_data, RST_ID_FROM_HTTP_1);
	}
	vm = vlib_get_main();
	/*First check whether reset by upstream*/
	if (hili_session_is_reset(conn)) {
		htp_pipe_debug_print("hili_ss is reseted");
		if (http_data->rst_code == 0) {
			if (conn->reset_errorcode) {
				http_data->rst_code = conn->reset_errorcode;
			} else {
				http_data->rst_code = RST_ID_FROM_HTTP_2;
			}
		}
		dproxy_http_error(http_data);
		conn->rx_cb_func = NULL;
		return NGX_OK;
	}
	//New added,different from another project, here should consider the upstream side breakup pkt coming after response ?
	if (http_data->upstream->current_body_length == http_data->req.headers_out.content_length_n) {
		goto checktcpevent;
	}
	/*Do the header and body filters if there are and now just write packet down*/
	/*Second handle response*/

	if (PREDICT_TRUE(http_data->header_sent)) {
		/*here process the body from upstream*/
		if (hili_session_send_window(http_data->reqcon) > 0) {
			len = hili_session_read(vm, conn, &mb);
			if (len > 0) {
				//dproxy_mbuf_set_alloc_id_all(mb, DPROXY_MBUF_ALLOC_ID_HTTP_2);
				if (hili_session_write(vm, http_data->reqcon, mb, len) < 0) {
					//dproxy_mbuf_free_memtrace(mb);
					vlib_buffer_hili_free_one_buffer(vm, mb);
					return NGX_ERROR;
				}
				http_data->upstream->current_body_length += len;
				if (http_data->upstream->current_body_length == http_data->req.headers_out.content_length_n) {
					dproxy_http_finalize_request(vm, http_data, &http_data->req, 0);/*this function will also call upstream finalize*/
				}
				if (http_data->upstream->current_body_length > http_data->req.headers_out.content_length_n) {
					htp_pipe_debug_print("%s:%d body len received > content_length\n", __func__, __LINE__);
				}
			} else {
				htp_pipe_debug_print("read length <= 0");
			}
		} else {
			htp_pipe_debug_print("cons_side->reqcon send window <= 0");
		}
	} else {
		dproxy_http_upstream_process_header(vm, http_data->upstream);
		if (http_data->upstream->current_body_length == http_data->req.headers_out.content_length_n) {
			dproxy_http_finalize_request(vm, http_data, &http_data->req, 0);/*this function will also call upstream finalize*/
		}
#if 0
		if (cons_side->upstream->current_body_length > cons_side->req.headers_out.content_length_n) {
			RTE_LOG(CRIT, HTTP, "%s:%d body len received > content_length\n", __func__, __LINE__);
		}
#endif
	}

checktcpevent:
	/*The handle the PIPE FIN */
	if (dproxy_http_pipe_fin_first_coming(http_data)) {
		http_data->flags |= HTTP_FLAG_HANDLED_PIPE_FIN;
		if (http_data->flags & HTTP_FLAG_ACTIVE_CLOSE) {
			htp_pipe_debug_print("had process active fin case");
			return NGX_ERROR;
		}
		if (http_data->flags & HTTP_FLAG_PASSIVE_CLOSE) {
			//curth_myhttp_stats.dproxy_myhttp_stats_pipe_pasv_close++;
			dproxy_http_close(http_data);
		} else {
			http_data->flags |= HTTP_FLAG_ACTIVE_CLOSE;
			/*upstream side FIN first, then we send FIN to upstream without waiting for the client side FIN*/
			//curth_myhttp_stats.dproxy_myhttp_stats_pipe_act_close++;
			dproxy_http_close(http_data);
		}
	}


	return NGX_OK;
}

static int htproxy_pipe_max_buffer = 16384;

static int
dproxy_http_request_setup_pipe(vlib_main_t *vm, http_parse_data_t *http_data, vlib_buffer_t *mb, u8 thread_index)
{
	session_t *hssp_local;
	session_t *hssp_remote;

	//hssp_local = dproxy_session_new(SD_IPPROTO_PIPE);
	hssp_local = session_alloc(thread_index);
	if (hssp_local == NULL) {
		//curth_myhttp_stats.dproxy_myhttp_stats_pipe_alloc_fail++;
		LINE_TRACE;
		// TODO handle the error case like : dproxy_http_error;
	}
	//hssp_remote = dproxy_session_new(SD_IPPROTO_PIPE);
	hssp_remote = session_alloc(thread_index);
	if (hssp_remote == NULL) {
		LINE_TRACE;
		session_free(hssp_local);
		//curth_myhttp_stats.dproxy_myhttp_stats_pipe_alloc_fail++;
		// TODO handle the error case like : dproxy_http_error;
	}

	hili_session_set_session_state(hssp_local, SESSION_STATE_CONNECTING);
	hili_session_set_session_state(hssp_remote, SESSION_STATE_CONNECTING);
	hssp_local->hili_type |= SS_PIPE;
	hssp_remote->hili_type |= SS_PIPE;

	hssp_local->hili_pipe_session_state = SESSION_PIPE_STATE_EST;
	hssp_remote->hili_pipe_session_state = SESSION_PIPE_STATE_EST;


	//hili_session_pipe_fill_basic_info(hssp_local, hssp_remote, http_data->reqcon);
	hssp_local->sendenddata = hssp_remote->sendenddata = 0;
	hssp_local->fwds = hssp_remote;
	hssp_remote->fwds = hssp_local;
	hssp_local->rx_cb_func = dproxy_http_pipe_input;
	hssp_remote->rx_cb_func = htproxy_session_forward_handler;
	
	hssp_local->cons_side = http_data;
	//hssp_local->conn_vs = hssp_remote->conn_vs = ((session_t *)(http_data->reqcon))->conn_vs;
	//hssp_remote->rx_cb_func(hssp_remote);
	http_data->pipe = hssp_local;

	if (hili_session_current_status(http_data->pipe) == HILI_SESSION_CUR_BREAKUP) {
		/* other side already closed or reset connection */
		hili_session_close(http_data->pipe);
		// TODO handle the error case like : dproxy_http_error;
	}

	((session_t *)(http_data->pipe))->sendrightwin = htproxy_pipe_max_buffer;
	((session_t *)(http_data->pipe))->fwds->sendrightwin = htproxy_pipe_max_buffer;

	hssp_remote->cons_side = http_data->upstream->peer;
	http_data->upstream->peer->cons_side = hssp_remote;
	//tlsp->pipe->cons_side = tlsp;
	/*give the mb to remote side which will send out to peer when peer conn estiblished*/
	//dproxy_session_enqueue_mbuf(&hssp_remote->recv_head_b, &hssp_remote->recv_tail_b, mb);
	hili_session_tcp_chain_recv_vb(vm, hssp_remote, mb);
	hssp_remote->sendenddata += vlib_buffer_length_in_chain(vm, mb);

	/* send_request_handler above only put the req to rpipe recv queue, it can be sent out by new 3whs
	 * and keepalive case we should push it.
	*/
	if (http_data->upstream->dp_ups_flags & DP_UPSTREAM_USE_KEEPALIVE) {
		hili_session_raise_event(hssp_remote, TQ_TYPE_PIPE_TOUCH_APP);
	}

	return NGX_OK;
}

static void dproxy_http_upstream_send_request_handler(vlib_main_t *vm, http_parse_data_t *http_data, u8 thread_index)
{
	FUNC_TRACE;
	// TODO  if timeout  call ngx_http_upstream_finalize_request like nginx
	vlib_buffer_t *mb = NULL;
	dproxy_http_upstream_prepare_request(http_data, &mb);
	if (mb == NULL) {
		htp_ups_debug_print("%s:%d failed to prepare request\n", __func__,__LINE__);
	}

	if (ngx_list_init(&http_data->req.headers_out.headers, http_data->req.pool, 20, sizeof(ngx_table_elt_t)) != NGX_OK) {
		htp_ups_debug_print("Failed to r->headers_out.headers\n");
		return;
	}
	if (http_data->tobesent_mb) {// TODO , tobesent_mb contain next new request case should be considered.
		htp_ups_debug_print("%s:%d chain the body buffer to header buffer\n", __func__, __LINE__);
		#if 0
		if (rte_pktmbuf_chain(mb, http_data->tobesent_mb)) {
			curth_myhttp_stats.dproxy_myhttp_stats_chain_reqbd_fail++;
			RTE_LOG(ERR, HTTP, "%s:%d Failed to chain http_data->tobesent_mb to request header mbuf\n", __func__, __LINE__);
			dproxy_mbuf_free_memtrace(mb);
			dproxy_mbuf_free_memtrace(http_data->tobesent_mb);
			http_data->tobesent_mb = NULL;
			return;
		}
		#endif
		vlib_buffer_hili_chain(vm, mb, http_data->tobesent_mb);
	}
	dproxy_http_request_setup_pipe(vm, http_data, mb, thread_index);//TODO check the return value
	hili_session_set_session_state(http_data->pipe, SESSION_STATE_READY);
	hili_session_set_session_state(((session_t *)(http_data->pipe))->fwds, SESSION_STATE_READY);
	http_data->upstream->read_event_handler = htproxy_session_forward_handler;
	http_data->upstream->write_event_handler = htproxy_session_forward_handler;
	return;
}

int dproxy_http_upstream_handler(session_t *conn)
{
	htp_ups_debug_print("%s enter\n", __func__);
	if (conn->write) {
		//upstream->write_event_handler(conn);//htproxy_session_forward_handler
		htp_ups_debug_print("%s write set, start to call write_event_handler\n", __func__);
		htproxy_session_forward_handler(conn);
		conn->write = 0;
	} else {
		//upstream->read_event_handler(conn);//htproxy_session_forward_handler
		htp_ups_debug_print("%s read set, start to call read_event_handler\n", __func__);
		htproxy_session_forward_handler(conn);
		conn->read = 0;
	}

	if (conn->rx_cb_func && hili_session_is_leaving(conn)) {
		//TODO caogw
		htp_ups_debug_print("%s http request side is leaving\n", __func__);
		/*upstream is thin layer, so let http_parse side to free the ups obj*/
		//dproxy_http_req_upstream_free(upstream);
		conn->rx_cb_func = NULL;
	}

	return EHTTP_MBUF_USED;
}

static void dproxy_http_reset_requqest(ngx_http_request_t *req)
{
	if (req->method == NGX_HTTP_GET ) {
		//curth_myhttp_stats.dproxy_myhttp_stats_get++;
	} else if (req->method == NGX_HTTP_POST) {
		//curth_myhttp_stats.dproxy_myhttp_stats_post++;
	} else {
		//curth_myhttp_stats.dproxy_myhttp_stats_method++;
	}
	req->method = 0;
	req->state = 0;
}

static void dproxy_http_reset_parse_data(vlib_main_t *vm, http_parse_data_t *parse_data)
{
	parse_data->body_start_mb = NULL;
	parse_data->body_start_pos = NULL;
	if (parse_data->parsing_req_mb) {
		//dproxy_mbuf_free_memtrace(parse_data->parsing_req_mb);
		vlib_buffer_hili_free_one_buffer(vm, parse_data->parsing_req_mb);
		parse_data->parsing_req_mb = NULL;
	}
	parse_data->last_parsed_mbuf = NULL;

	/*reset some field for new coming request*/
	parse_data->current_parse_state = PARSE_STATE_REQ_START;
	parse_data->content_length = 0;
	parse_data->current_body_length = 0;
	parse_data->is_chunked = 0;
	parse_data->content_length_exists = 0;
	parse_data->flags = 0;
	dproxy_http_reset_requqest(&parse_data->req);
}

static void dproxy_http_init_request(ngx_http_request_t *r)
{
	r->method = NGX_HTTP_UNKNOWN;
	r->http_version = NGX_HTTP_VERSION_10;

	r->headers_in.content_length_n = -1;
	r->headers_in.keep_alive_n = -1;
	r->headers_out.content_length_n = -1;
	r->headers_out.last_modified_time = -1;

	r->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;
	r->subrequests = NGX_HTTP_MAX_SUBREQUESTS + 1;

	r->http_state = NGX_HTTP_READING_REQUEST_STATE;
}

void dproxy_http_longest_transiction_check(void)
{
	heap_entry_t *cur_heap_top_e;
	hed_8tuple_t *two_conn_info;
	int i;

	printf("%-10s\t%-10s\t%-5s\t%-10s\t%-5s\t%-10s\t%-5s\t%-10s\t%-5s\t\n", "totaltime", "REQlocalIP", "port", "REQremotIP", "port",  "RESlocalIP", "port", "RESremotIP", "port");
	for (i = 0; i < g_min_heap_size; i++) {
		cur_heap_top_e = popHeap(g_http_min_heap);
		two_conn_info = (hed_8tuple_t *)cur_heap_top_e->entry_data;
		printf("%-10lu\t%-10x\t%-5d\t%-10x\t%-5d\t%-10x\t%-5d\t%-10x\t%-5d\t\n", 
				cur_heap_top_e->key, two_conn_info->req_info.local_ip, two_conn_info->req_info.local_port,
				two_conn_info->req_info.remote_ip, two_conn_info->req_info.remote_port,
				two_conn_info->ups_info.local_ip, two_conn_info->ups_info.local_port, 
				two_conn_info->ups_info.remote_ip, two_conn_info->ups_info.remote_port);
	}
	printf("\n");
	return;
}

static void dproxy_http_release_resource(session_t *conn)
{
	FUNC_TRACE;
	vlib_main_t *vm;
	if (conn->http_data == NULL) {
		htp_req_debug_print("%s conn->http_data is NULL\n", __func__);
		return;
	}

	vm = vlib_get_main();

	if (conn->http_data->next_request) {
		if (conn->http_data->parsing_req_mb && conn->http_data->parsing_req_mb != conn->http_data->next_request) {
			//dproxy_mbuf_free_memtrace(conn->http_data->parsing_req_mb);
			vlib_buffer_hili_free_one_buffer(vm, conn->http_data->parsing_req_mb);
			conn->http_data->parsing_req_mb = NULL;
		}
		//dproxy_mbuf_free_memtrace(conn->http_data->next_request);
		vlib_buffer_hili_free_one_buffer(vm, conn->http_data->next_request);
		conn->http_data->next_request = NULL;
		htp_req_debug_print("%s Free http_data->next_request\n", __func__);
	}

	if (conn->http_data->req_handled > 1) {
		//curth_myhttp_stats.dproxy_myhttp_stats_mulreq_con++;
	}

	if (conn->http_data->upstream) {
		dproxy_http_upstream_t *dp_upstream;
		dp_upstream = conn->http_data->upstream;
		if (dp_upstream->parsing_resp_mb && dp_upstream->parsing_resp_mb != dp_upstream->resp_next_mb) {
			//dproxy_mbuf_free_memtrace(dp_upstream->parsing_resp_mb);
			vlib_buffer_hili_free_one_buffer(vm, dp_upstream->parsing_resp_mb);
			dp_upstream->parsing_resp_mb = NULL;
		}
		if (dp_upstream->resp_next_mb) {
			//dproxy_mbuf_free_memtrace(dp_upstream->resp_next_mb);
			vlib_buffer_hili_free_one_buffer(vm, dp_upstream->resp_next_mb);
			dp_upstream->resp_next_mb = NULL;
		}

		//dproxy_http_req_upstream_free(dp_upstream);
		proxy_http_upstream_free(dp_upstream);
		conn->http_data->upstream = NULL;
	}

	if (conn->http_data->req.upstream) {
		//ngx_http_req_upstream_free(conn->http_data->req.upstream);
		ngx_http_upstream_free(conn->http_data->req.upstream);
		conn->http_data->req.upstream = NULL;
	}

	//dproxy_http_parse_data_free(conn->http_data);
	http_data_free(conn->http_data);
	conn->http_data = NULL;

}


ngx_pool_t *g_ngx_pool;
ngx_log_t g_ngx_log;

int dproxy_http_init(void)
{
	int i;
	g_ngx_pool = ngx_create_pool(896, &g_ngx_log);/*actully, It will get 1024 bytes*/
	myngx_http_init_headers_in_hash(g_ngx_pool);
	myngx_http_init_upstream_headers_in_hash(g_ngx_pool);

	hili_minheapt_init();
	g_http_min_heap = createHeap(g_min_heap_size);
	for (i = 0; i < g_min_heap_size; i++) {
		g_min_heap_init_arra[i].key = i;
		pushHeap(g_http_min_heap, &g_min_heap_init_arra[i]);
	}

	return EHTTP_OK;
}

//call this to enable http proxy when http reverse/forward configed 


/*************record mem function************************************/

/***************ssl record mem function end**********************/

static clib_error_t *
htproxy_data_manager_main_enable(vlib_main_t *vm)
{
	htproxy_data_manager_main_t *htproxy_dmm = &htproxy_data_manager_main;

	vlib_thread_main_t *vtm = vlib_get_thread_main ();
	u32 num_threads, preallocated_data_per_worker;
	int i, j;

	num_threads = 1 /* main thread */  + vtm->n_threads;

	if (num_threads < 1) {
		return clib_error_return (0, "n_thread_stacks not set");
	}

	htproxy_dmm->is_enabled = 1;
	/* configure per-thread ** vectors */
	vec_validate (htproxy_dmm->http_parse_data_pools, num_threads - 1);
	vec_validate (htproxy_dmm->htproxy_upstream_pools, num_threads - 1);
	vec_validate (htproxy_dmm->htproxy_ngx_upstream_pools, num_threads - 1);
	vec_validate (htproxy_dmm->ups_session_cache, num_threads - 1);
	vec_validate (htproxy_dmm->req_session_cache, num_threads - 1);
#if 0
#endif
	vec_validate (htproxy_dmm->http_parse_data_peekers_rw_locks, num_threads - 1);
	vec_validate (htproxy_dmm->htproxy_upstream_peekers_rw_locks, num_threads - 1);
	vec_validate (htproxy_dmm->htproxy_ngx_upstream_peekers_rw_locks, num_threads - 1);

	if (num_threads > 1) {
		for (i = 0; i < num_threads; i++) {
			clib_rwlock_init(&htproxy_dmm->http_parse_data_peekers_rw_locks[i]);
			clib_rwlock_init(&htproxy_dmm->htproxy_upstream_peekers_rw_locks[i]);
			clib_rwlock_init(&htproxy_dmm->htproxy_ngx_upstream_peekers_rw_locks[i]);
		}
		for (i = 0; i < num_threads; i++) {
			my_ngx_queue_init(&htproxy_dmm->req_session_cache[i]);
			my_ngx_queue_init(&htproxy_dmm->ups_session_cache[i]);
		}
	}

	if (htproxy_dmm->preallocated_http_pdata) {
		ft_printf("htproxy_dmm->preallocated_http_pdata config value : %u\n", htproxy_dmm->preallocated_http_pdata);
		if (num_threads == 1) {
			pool_init_fixed (htproxy_dmm->http_parse_data_pools[0], htproxy_dmm->preallocated_http_pdata);
		} else {
			preallocated_data_per_worker = (1.1 * (f64) htproxy_dmm->preallocated_http_pdata/ (f64) (num_threads - 1));
			for (j = 1; j < num_threads; j++) {
				pool_init_fixed (htproxy_dmm->http_parse_data_pools[j], preallocated_data_per_worker);
			}

		}
	}

	if (htproxy_dmm->preallocated_htproxy_upstream) {
		ft_printf("htproxy_dmm->preallocated_htproxy_upstream config value : %u\n", htproxy_dmm->preallocated_htproxy_upstream);
		if (num_threads == 1) {
			pool_init_fixed (htproxy_dmm->htproxy_upstream_pools[0], htproxy_dmm->preallocated_htproxy_upstream);
		} else {
			preallocated_data_per_worker = (1.1 * (f64) htproxy_dmm->preallocated_htproxy_upstream/ (f64) (num_threads - 1));
			for (j = 1; j < num_threads; j++) {
				pool_init_fixed (htproxy_dmm->htproxy_upstream_pools[j], preallocated_data_per_worker);
			}

		}
	}

	if (htproxy_dmm->preallocated_ngx_upstream) {
		ft_printf("htproxy_dmm->preallocated_ngx_upstream config value : %u\n", htproxy_dmm->preallocated_ngx_upstream);
		if (num_threads == 1) {
			pool_init_fixed (htproxy_dmm->htproxy_ngx_upstream_pools[0], htproxy_dmm->preallocated_ngx_upstream);
		} else {
			preallocated_data_per_worker = (1.1 * (f64) htproxy_dmm->preallocated_ngx_upstream/ (f64) (num_threads - 1));
			for (j = 1; j < num_threads; j++) {
				pool_init_fixed (htproxy_dmm->htproxy_ngx_upstream_pools[j], preallocated_data_per_worker);
			}

		}
	}

	htproxy_upstream_init();
	htproxy_location_init();
	htproxy_server_init();
	dproxy_http_init();
}


clib_error_t *
hili_htproxy_enable_disable (vlib_main_t * vm, u8 is_en)
{
	clib_error_t *error = 0;
	if (is_en) {
		if (htproxy_data_manager_main.is_enabled) {
			LINE_TRACE;
			return 0;
		}
		LINE_TRACE;
		error = htproxy_data_manager_main_enable(vm);
	} else {
		LINE_TRACE;
	}

	return error;
}

http_parse_data_t *
http_data_alloc(u32 thread_index)
{
	FUNC_TRACE;
	htproxy_data_manager_main_t *htp_dmm = &htproxy_data_manager_main;
	http_parse_data_t *s;
	u8 will_expand = 0;

	pool_get_aligned_will_expand (htp_dmm->http_parse_data_pools[thread_index], will_expand, CLIB_CACHE_LINE_BYTES);
	/* If we have peekers, let them finish */
	if (PREDICT_FALSE (will_expand && vlib_num_workers ())) {
		clib_rwlock_writer_lock (&htp_dmm->http_parse_data_peekers_rw_locks[thread_index]);
		pool_get_aligned (htproxy_data_manager_main.http_parse_data_pools[thread_index], s, CLIB_CACHE_LINE_BYTES);
		clib_rwlock_writer_unlock (&htp_dmm->http_parse_data_peekers_rw_locks[thread_index]);
	}
	else {
		pool_get_aligned (htproxy_data_manager_main.http_parse_data_pools[thread_index], s, CLIB_CACHE_LINE_BYTES);
	}

	memset (s, 0, sizeof (*s));
	s->http_data_index = s - htproxy_data_manager_main.http_parse_data_pools[thread_index];
	s->thread_index = thread_index;
	return s;
}

void
http_data_free(http_parse_data_t * s)
{
	pool_put (htproxy_data_manager_main.http_parse_data_pools[s->thread_index], s);
	if (CLIB_DEBUG) {
		memset (s, 0xFA, sizeof (*s));
	}
}


//nginx upstream wrapper alloc and free

ngx_http_upstream_t *
ngx_http_upstream_alloc(u32 thread_index)
{
	FUNC_TRACE;
	htproxy_data_manager_main_t *htp_dmm = &htproxy_data_manager_main;
	ngx_http_upstream_wrapper_t *s;
	ngx_http_upstream_t *ngx_ups;
	u8 will_expand = 0;

	pool_get_aligned_will_expand (htp_dmm->htproxy_ngx_upstream_pools[thread_index], will_expand, CLIB_CACHE_LINE_BYTES);
	/* If we have peekers, let them finish */
	if (PREDICT_FALSE (will_expand && vlib_num_workers ())) {
		clib_rwlock_writer_lock (&htp_dmm->htproxy_ngx_upstream_peekers_rw_locks[thread_index]);
		pool_get_aligned (htproxy_data_manager_main.htproxy_ngx_upstream_pools[thread_index], s, CLIB_CACHE_LINE_BYTES);
		clib_rwlock_writer_unlock (&htp_dmm->htproxy_ngx_upstream_peekers_rw_locks[thread_index]);
	}
	else {
		pool_get_aligned (htproxy_data_manager_main.htproxy_ngx_upstream_pools[thread_index], s, CLIB_CACHE_LINE_BYTES);
	}

	memset (s, 0, sizeof (*s));
	s->ng_upswr_index = s - htproxy_data_manager_main.htproxy_ngx_upstream_pools[thread_index];
	s->thread_index = thread_index;

	ngx_ups = &s->http_upstream;
	ngx_ups->headers_in.content_length_n = -1;
	ngx_ups->headers_in.last_modified_time = -1;
	return ngx_ups;
}

#define ngx_http_upstream_wrapper_data(ngx_ups)                                                 \
    (ngx_http_upstream_wrapper_t *)                                                  \
        ((u_char *) (ngx_ups) - offsetof(ngx_http_upstream_wrapper_t, http_upstream))

void
ngx_http_upstream_free(ngx_http_upstream_t * ngx_ups)
{
	ngx_http_upstream_wrapper_t *s = ngx_http_upstream_wrapper_data(ngx_ups);
	pool_put (htproxy_data_manager_main.htproxy_ngx_upstream_pools[s->thread_index], s);
	if (CLIB_DEBUG) {
		memset (s, 0xFA, sizeof (*s));
	}
}

//htproxy upstream alloc and free
dproxy_http_upstream_t *
proxy_http_upstream_alloc(u8 thread_index)
{
	FUNC_TRACE;
	htproxy_data_manager_main_t *htp_dmm = &htproxy_data_manager_main;
	dproxy_http_upstream_t *s;
	u8 will_expand = 0;

	pool_get_aligned_will_expand (htp_dmm->htproxy_upstream_pools[thread_index], will_expand, CLIB_CACHE_LINE_BYTES);
	/* If we have peekers, let them finish */
	if (PREDICT_FALSE (will_expand && vlib_num_workers ())) {
		clib_rwlock_writer_lock (&htp_dmm->htproxy_upstream_peekers_rw_locks[thread_index]);
		pool_get_aligned (htproxy_data_manager_main.htproxy_upstream_pools[thread_index], s, CLIB_CACHE_LINE_BYTES);
		clib_rwlock_writer_unlock (&htp_dmm->htproxy_upstream_peekers_rw_locks[thread_index]);
	}
	else {
		pool_get_aligned (htproxy_data_manager_main.htproxy_upstream_pools[thread_index], s, CLIB_CACHE_LINE_BYTES);
	}

	memset (s, 0, sizeof (*s));
	s->dp_ups_index = s - htproxy_data_manager_main.htproxy_upstream_pools[thread_index];
	s->thread_index = thread_index;
	return s;
}

void
proxy_http_upstream_free(dproxy_http_upstream_t * s)
{
	pool_put (htproxy_data_manager_main.htproxy_upstream_pools[s->thread_index], s);
	if (CLIB_DEBUG) {
		memset (s, 0xFA, sizeof (*s));
	}
}

/*edge start*/

static int htproxy_setup_upstream(vlib_main_t *vm, session_t *conn, session_t *new_conn)
{
	htp_req_debug_print("%s 3whs finish let's setup upstream!\n", __func__);
	//dproxy_http_upstream_t *upstream = dproxy_http_req_upstream_new();
	dproxy_http_upstream_t *upstream = proxy_http_upstream_alloc(conn->thread_index);
	if (upstream == NULL) {
		htp_req_debug_print("%s:%d dproxy_http_req_upstream_new failed!\n", __func__, __LINE__);
		htp_ups_debug_print("%s:%d dproxy_http_req_upstream_new failed!\n", __func__, __LINE__);
		return EHTTP_NOMEM;
	}
	if (new_conn->hili_flags & DPROXY_HTTP_KEEPALIVE) {
		upstream->dp_ups_flags |= DP_UPSTREAM_USE_KEEPALIVE;
	}
	//conn->http_data->req.upstream = ngx_http_req_upstream_new();//used for parse upstream header
	conn->http_data->req.upstream = ngx_http_upstream_alloc(conn->thread_index);//used for parse upstream header
	if (conn->http_data->req.upstream == NULL) {
		htp_req_debug_print("%s:%d ngx_http_req_upstream_new failed!\n", __func__, __LINE__);
		htp_ups_debug_print("%s:%d ngx_http_req_upstream_new failed!\n", __func__, __LINE__);
		return EHTTP_NOMEM;
	}
	conn->http_data->req.main = &conn->http_data->req;
	/* From client to rs 
	conn--__cons_side__ or http_data -> http_parse_data-__upstream__ -> http_upstream-__peer__-> conn_of_rs
	*/
	
	conn->http_data->upstream = upstream;
	upstream->peer = new_conn;
	
	/* From rs to client
	conn_of_rs--__cons_side__-> http_upstream -__http_data__-> http_parse_data -__reqconn__->conn_of_vs
	*/
	new_conn->cons_side = upstream;
	new_conn->rx_cb_func = dproxy_http_upstream_handler;
	upstream->http_data = conn->http_data;
	upstream->http_data->reqcon = conn;


	dproxy_http_upstream_send_request_handler(vm, conn->http_data, conn->thread_index);
	dproxy_http_reset_parse_data(vm, conn->http_data);
	if (conn->http_data->next_request != NULL) {
		conn->http_data->parsing_req_mb = conn->http_data->next_request;
	}
	return EHTTP_OK;
}

/* @param hili_ss must be a TCP stream session and curreent state is set
    to READ if don't fail to active open;
   @ tp_cons_index the tls proxy consumer side structure index
   @ tid the thread
 * return 0, everything OK, else something error, no matter with is_fail
 */
int
htproxy_handle_active_open_result(session_t *hili_ss, u32 tp_cons_index, u32 tid, u8 is_fail)
{
	FUNC_TRACE;
	session_t *tmp_ss, *consume_ss;
	tlsproxy_cons_t *tlsc;
	int error = 0;
	uint16_t rst_code = RST_ID_HTTP_CLIENT_0e01;
	vlib_main_t *vm = vlib_get_main();
	/*If is_fail is true, then hili_ss should NULL*/
	tlsc = tlsproxy_cons_get(tp_cons_index, tid);
	tmp_ss = session_get(tlsc->tmp_session_index, tid);
	hili_ss->hili_flags |= SS_TCP_AS_CLIENT;
	hili_ss->conn_rs =  tmp_ss->conn_rs;
	if (tlsc->cons_side_type == SESSION_CONSUME_TYPE) {
		LINE_TRACE;
		consume_ss = session_get(tlsc->cons_side_index, tid);
		if (is_fail) {
			LINE_TRACE;
			consume_ss->cons_side = NULL;
			hili_session_terminate(consume_ss, rst_code);
		} else {
			LINE_TRACE;
			if ((error = htproxy_setup_upstream(vm, consume_ss, hili_ss)) == EHTTP_OK) {
				htp_ups_debug_print("htp_setup_stream OK, let's tell the upstream write op is permit");
				hili_ss->write = 1;
				hili_ss->rx_cb_func(hili_ss);//For upstream, this call will write the http request donw, so 3rd ACK packet will get the payload
			} else {
				htp_ups_debug_print("htp_setup_stream error!!");
			}
		}
	} else {
		LINE_TRACE;
		ft_printf("Something wrong !\n");
		error = -1;
	}

	hili_session_cleanup(tmp_ss);
	session_free(tmp_ss);
	tlsproxy_cons_free(tlsc);

	return error;
}


always_inline session_t *
htproxy_create_fwd_stream_multi_rs(session_endpoint_t * rmt, struct session_ *hili_ss)
{
	FUNC_TRACE;
	int rv;
	session_t *new_ss;
	tlsproxy_cons_t *tlsc;
	new_ss = session_alloc(hili_ss->thread_index);
	new_ss->hili_flags |= SS_TCP_AS_CLIENT_TMP;
	hili_session_set_session_state(new_ss, SESSION_STATE_CONNECTING);
	new_ss->rx_cb_func = hili_ss->rx_cb_func;
	tlsc = tlsproxy_cons_alloc(hili_ss->thread_index);

	tlsc->cons_side_type = SESSION_CONSUME_TYPE;
	tlsc->cons_side_index = hili_ss->session_index;

	tlsc->tmp_session_index = new_ss->session_index;  /*take this used after TCP est*/
	tlsc->act_open_cb_func = htproxy_handle_active_open_result;
	ft_printf("tlsinfo锛歝ons_side_index %u, tmp_session_index %u, tlsproxy_cons_index %u\n",
				tlsc->cons_side_index, tlsc->tmp_session_index, tlsc->tlsproxy_cons_index);

	if  ((rv = hili_session_open_vc_tlsproxy(rmt, tlsc->tlsproxy_cons_index))) {
		LINE_TRACE;
		ft_printf("Failed to active connect to the real server\n");
		return NULL;
	} else {
		ft_printf("hili_ss %p, new_ss %p\n", hili_ss, new_ss);
		return new_ss;
	}
}

static htproxy_real_service_t *htproxy_server_lb_hi(session_t *hili_ss, http_upstream_runtime_t *ups_conf)
{
	FUNC_TRACE;
	htproxy_real_service_t *select_rs;

	transport_connection_t *tc;

	tc = session_get_transport(hili_ss);
	select_rs = &ups_conf->rs_array[tc->rmt_ip.ip4.as_u32 % ups_conf->rs_num];
	return select_rs;
}

static htproxy_real_service_t *htproxy_server_lb_rr(http_upstream_runtime_t *ups_conf)
{
	FUNC_TRACE;
	//TODO enhancement, it's golabl, should use per-thread cur_lb_rs to record the next rs select by current thread.
	htproxy_real_service_t *select_rs;
	select_rs = &ups_conf->rs_array[ups_conf->cur_lb_rs++];
	ups_conf->cur_lb_rs %= ups_conf->rs_num;
	return select_rs;
}

static htproxy_real_service_t *htproxy_server_load_balance(session_t *hili_ss, http_upstream_runtime_t *ups_conf)
{
	FUNC_TRACE;
	switch(ups_conf->lb_method) {
		case HTTP_UPSTREAM_RR_METHOD:
		case HTTP_UPSTREAM_WRR_METHOD:
			return htproxy_server_lb_rr(ups_conf);
		case HTTP_UPSTREAM_HIP_METHOD:
			return htproxy_server_lb_hi(hili_ss, ups_conf);
		default:
			htp_ups_debug_print("unspported HTTP UPSTREM load balance method");
	}
}

static int ups_keepalive_enable = 0;
#if 0
#define this_upscon_cache             (RTE_PER_LCORE(upstream_conn_cache))
static RTE_DEFINE_PER_LCORE(my_ngx_queue_t, upstream_conn_cache);
#endif
static int hili_tcp_upstream_free_keepalive_peer(session_t *conn)
{
	//ngx_queue_insert_head(&this_upscon_cache, &conn->keepalive_queue);
	htproxy_data_manager_main_t *htproxy_dmm = &htproxy_data_manager_main;
	my_ngx_queue_insert_head(&htproxy_dmm->ups_session_cache[conn->thread_index], &conn->keepalive_queue);

	return 0;
}

session_t * hili_tcp_upstream_get_keepalive_peer(session_t *req_conn)
{
	my_ngx_queue_t  *q;
	session_t *conn;
	htproxy_data_manager_main_t *htproxy_dmm = &htproxy_data_manager_main;
	if (ngx_queue_empty(&htproxy_dmm->ups_session_cache[req_conn->thread_index])) {
		htp_ups_debug_print("%s upstream_conn_cache is empty, return NULL\n", __func__);
		return NULL;
	}

	q = ngx_queue_head(&htproxy_dmm->ups_session_cache[req_conn->thread_index]);
	conn = ngx_queue_data(q, session_t, keepalive_queue);
	ngx_queue_remove(&conn->keepalive_queue);
	htp_ups_debug_print("%s get a conn from upstream_conn_cache\n", __func__);
	return conn;
}

always_inline session_t *
htproxy_session_start_upstream_session(session_t *hili_ss)
{
	FUNC_TRACE;
	session_t *new_ss;
	//hili_lb_config_t *lbp = hili_lb_config_get(hili_ss->opaque, 0);
	htproxy_real_service_t *htp_rs;
	http_upstream_runtime_t *ups_conf = hili_ss->http_data->http_location->rt_upstream;

	htp_rs = htproxy_server_load_balance(hili_ss, ups_conf);
	if (htp_rs->rs_type == HILI_LB_TCP_RS) {
		LINE_TRACE;
		if  (htp_rs->vs_type == HILI_LB_TCP_VS) {
			session_log_debug("It's a TCP<->TCP reverse proxy case\n");
		} else if (htp_rs->vs_type == HILI_LB_TLS_VS) {
			session_log_debug("It's a TLS<->TCP reverse proxy case\n");
		}
		if (ups_keepalive_enable) {
			new_ss = hili_tcp_upstream_get_keepalive_peer(hili_ss);
			if (new_ss == NULL) {
				new_ss = htproxy_create_fwd_stream_multi_rs(&htp_rs->client_sep , hili_ss);
			} else {
				new_ss->hili_flags |= DPROXY_HTTP_KEEPALIVE;
			}
		} else { 
			new_ss = htproxy_create_fwd_stream_multi_rs(&htp_rs->client_sep , hili_ss);
			if (new_ss == NULL) {
				return NULL;
			}
		}
		new_ss->hili_type = SS_TCP;
		new_ss->conn_rs = htp_rs;
		new_ss->rx_cb_func = hili_ss->rx_cb_func;//hili_ss rx_cb_func is http_input, this should be change out of this func
	} else {
		session_log_warn("Unexpected case\n");
	}

	return new_ss;
}

/*edge end*/

int dproxy_http_input(session_t *conn)
{
	int len = 0;
	//int ret;
	int parse_result;
	vlib_buffer_t *mbuf;
	session_t *new_conn;
	ngx_int_t rc;
	vlib_main_t *vm = vlib_get_main();
	
	conn->hili_type = SS_TCP;
	if (hili_session_is_reset(conn)) {
		/*rx_rst will delete the conn when this return, so do nothing*/
		htp_req_debug_print("%s connection is reseted\n", __func__);
		if (conn->http_data != NULL) {
			dproxy_http_reset(conn->http_data);
		}
		//dproxy_http_parse_data_free(http_data);
		conn->rx_cb_func = NULL;
		return EHTTP_MBUF_NO_USE;
	}
	
	//conn->hili_flags |= DPROXY_CONN_PARSER_SIDE;
	len = hili_session_read(vm, conn, &mbuf);
	//dproxy_mbuf_set_alloc_id_all(mbuf, DPROXY_MBUF_ALLOC_ID_HTTP_1);
	if (len > 0) {
		if (conn->http_data == NULL) {
			//conn->http_data = dproxy_http_parse_data_new();
			conn->http_data = http_data_alloc(conn->thread_index);
			if (conn->http_data == NULL) {
				//dproxy_mbuf_free_memtrace(mbuf);
				vlib_buffer_hili_free_one_buffer(vm, mbuf);
				return EHTTP_NOMEM;
			}
			hili_session_set_session_state(conn, SESSION_STATE_READY);
			conn->http_data->req.pool = ngx_create_pool(4096, &conn->http_data->log);
			dproxy_http_init_request(&conn->http_data->req);
			hili_lb_config_t *lbp = hili_lb_config_get(conn->opaque, 0);
			conn->clenup_cb_func = dproxy_http_release_resource;
			//conn->http_data->conn_vs = conn->conn_vs;
			conn->http_data->lb_conf = lbp;
			conn->http_data->req_start_time = clib_cpu_time_now();
		}
		if (conn->http_data->parsing_req_mb == NULL) {
			htp_req_debug_print("%s The new request coming in, let's record the buffer\n", __func__);
			conn->http_data->current_parse_state = PARSE_STATE_REQ_START;
			conn->http_data->parsing_req_mb = mbuf;
		}

		/*EHTTP_CUR_INPUT_MESSAGE_PARSE_INCOMPLETE will make next_request not NULL*/
		if (conn->http_data->next_request == NULL) {
			htp_req_debug_print("%s http_data->next_request is NULL, use this mbuf as first\n", __func__);
			conn->http_data->next_request = mbuf;
		} else {
#if 0
			RTE_LOG(INFO, HTTP, "%s http_data->next_request NOT NULL, chain this mbuf to it\n", __func__);
			if (rte_pktmbuf_chain(conn->http_data->next_request, mbuf)) {
				RTE_LOG(ERR, HTTP, "%s Failed to chain this mbuf to http_data->next_request\n", __func__);
				dproxy_mbuf_free_memtrace(mbuf);
				//cur_th_http_stats.http_stats_l7_chain_inmb_fail++;
				curth_myhttp_stats.dproxy_myhttp_stats_chain_reqmb_fail++;
				return EHTTP_NOROOM;
			}
#endif
			vlib_buffer_hili_chain(vm, conn->http_data->next_request, mbuf);
		}

		while (conn->http_data->next_request != NULL) {
			vlib_buffer_t *remain = NULL;
			parse_result = dproxy_http_parse_request_message(vm, conn, conn->http_data->next_request, &remain);
			conn->http_data->next_request = remain;
			if(EHTTP_CUR_INPUT_MESSAGE_PARSE_INCOMPLETE == parse_result) {
				if (hili_session_is_leaving(conn)) {
					//cur_th_http_stats.http_stats_req_invalid++;
					htp_req_debug_print("%s Seem FIN coming in but still not complete, bad request!\n", __func__);
				}
				//hili_session_tcp_halfclose(conn);
				hili_session_terminate(conn, RST_ID_FROM_HTTP_4);
				//curth_myhttp_stats.dproxy_myhttp_stats_req_incomp++;
				htp_req_debug_print("%s There is no more mbuf to be used to parse the whole req_line/header/body, so break\n", __func__);
				break;
			} else if (parse_result < 0) {
				//dproxy_tcp_parser_conn_shutdown(conn);
				//curth_myhttp_stats.dproxy_myhttp_stats_req_invalid++;
				return EHTTP_INVPKT;
			} else if (EHTTP_CUR_INPUT_PARSED_A_REQ_RES == parse_result) {
				/*Happy things, we need to break up the mbuf chain*/
				//dproxy_http_taking_a_req_or_res(conn);
				conn->http_data->req_handled++;
				//curth_myhttp_stats.dproxy_myhttp_stats_req_handled++;
				htp_req_debug_print("%s There's a complete message, next message if have\n", __func__);
				if (conn->http_data->body_start_mb) {
					int offset = conn->http_data->body_start_pos - vlib_buffer_hili_mtod(conn->http_data->body_start_mb, char *);
					conn->http_data->tobesent_mb = dproxy_http_split_requests(vm, conn, conn->http_data->body_start_mb, offset);
				}
				if (conn->http_data->tobesent_mb == NULL) {
					htp_req_debug_print("%s:%d tobesent_mb is NULL\n", __func__, __LINE__);
				} else {
					htp_req_debug_print("%s:%d tobesent_mb is NOT NULL\n", __func__, __LINE__);
				}
				//conn->http_data->http_location = my_ngx_http_core_find_static_location(conn->http_data->req, conn->http_data->http_server->static_locations);
				rc = my_ngx_http_core_find_location(&conn->http_data->req, conn->http_data->http_server, &conn->http_data->http_location);
				if (rc == NGX_ERROR) {
					htp_req_debug_print("%s my_ngx_http_core_find_location failed!\n", __func__);
					break;
				}
				if (conn->cons_side == NULL) {
					//new_conn = dproxy_http_create_upstream_conn(conn);
					new_conn = htproxy_session_start_upstream_session(conn);
					if (new_conn) {
						//current the new_conn just a temp session, here just do some basic things, other job done after 2rd ACK coming
						htp_req_debug_print("%s htproxy_session_start_upstream_session success!\n", __func__);
						conn->rx_cb_func = dproxy_http_request_handler;
						conn->http_data->read_event_handler = dproxy_http_block_reading;
						conn->http_data->write_event_handler = dproxy_http_request_empty_handler;
						//otherthings move to htproxy_setup_upstream
						break;
					} else {
						htp_req_debug_print("%s:%d dproxy_http_create_upstream_conn failed!\n", __func__, __LINE__);
						htp_ups_debug_print("%s:%d dproxy_http_create_upstream_conn failed!\n", __func__, __LINE__);
						//TODO  upstream connect failed, send server internal error to client instead send RST.
						conn->http_data->reqcon = conn;
						conn->http_data->rst_code = RST_ID_FROM_HTTP_7;
						return dproxy_http_error(conn->http_data);
						
					}
				} else {
					htp_req_debug_print("%s:%d request side connection cons_side is not NULL\n", __func__, __LINE__);
				}
			} else {
				//curth_myhttp_stats.dproxy_myhttp_stats_req_unexp++;
				htp_req_debug_print("%s !!!!!!Something unknow happend !!!!!!!!\n", __func__);
			}
		}
	}else {/*read mbuf len <= 0*/
			if (hili_session_is_leaving(conn)) {
				if (conn->http_data == NULL) {/*it's fin just 3whs so here send fin back*/
					hili_session_halfclose(conn);
				} else {/*fin coming in with partial request,so here send rst back*/
					hili_session_terminate(conn, RST_ID_FROM_HTTP_5);
				}
			}
			htp_req_debug_print("%s !!!!!!hili_session_read len < 0 !!!!!!!!\n", __func__);
			//curth_myhttp_stats.dproxy_myhttp_stats_req_read_err++;
			return EHTTP_NOROOM;
	}

	return EHTTP_OK;
}

//start http proxy config option 

static clib_error_t *
htproxy_config_fn(vlib_main_t * vm, unformat_input_t * input)
{
  htproxy_data_manager_main_t *htp_dmm = &htproxy_data_manager_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "preallocated-http-pdata %d",
			 &htp_dmm->preallocated_http_pdata))
	;
    else if (unformat (input, "preallocated-htproxy-upstream %d",
			 &htp_dmm->preallocated_htproxy_upstream))
	;
    else if (unformat (input, "preallocated-ngx-upstream %d",
			 &htp_dmm->preallocated_ngx_upstream))
	;
	else
		return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

	return 0;
}

VLIB_CONFIG_FUNCTION (htproxy_config_fn, "htproxy");

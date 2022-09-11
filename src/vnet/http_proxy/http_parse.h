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
#ifndef __DPROXY_HTTP_PARSE_H__
#define __DPROXY_HTTP_PARSE_H__
#include <vnet/http_proxy/nginx/include/ngx_http.h>
#include <vnet/http_proxy/nginx/include/ngx_palloc.h>
#include <vnet/http_proxy/http_error_def.h>
#include <vnet/http_proxy/my_ngx_regex.h>

#include <vnet/session/session.h>

typedef enum {
		PARSE_STATE_REQ_START = 0,
		PARSE_STATE_RESP_START = 1,
		PARSE_STATE_HEADER_START = 2,
		PARSE_STATE_BODY_START = 3,
} PARSE_STATE_e;

/*
 * Defination http->flags.
 */
#define HTTP_FLAG_ACTIVE_CLOSE        0x00000001 /* PIPE recevie FIN first*/
#define HTTP_FLAG_PASSIVE_CLOSE       0x00000002 /* TCP  receive FIN first*/
#define HTTP_FLAG_HANDLED_PIPE_FIN      0x00000004 /*pipe input handle the FIN*/
#define HTTP_FLAG_HANDLE_TCP_FIN       0x00000008


typedef struct http_parse_data_s  http_parse_data_t;
typedef int (*ngx_http_req_handler_pt)(http_parse_data_t *r);

struct http_parse_data_s{
		int         content_length_exists:1;
		int			is_chunked:1;
		int header_sent:1;
		uint16_t rst_code;
		ngx_log_t log;/*here just used for ngx_create_pool parameter*/
		ngx_http_request_t req;
		struct dproxy_http_upstream_s *upstream;
		void *pipe;
		void *reqcon;
		ngx_http_req_handler_pt read_event_handler;
		ngx_http_req_handler_pt write_event_handler;

		hili_lb_config_t *lb_conf;
		struct http_server_runtime_s *http_server;
		struct http_location_runtime_s *http_location;
		my_ngx_pool_t *req_pool;
		//request_rec *ms_req;
		//conn_rec *ms_c;
		PARSE_STATE_e   current_parse_state;
		uint32_t	req_handled;
		uint64_t    flags;
		int         content_length;
		int         current_body_length;
		ngx_http_status_t status;
		u8	thread_index;
		u32 http_data_index;
		vlib_buffer_t *parsing_req_mb;		/*mbuf chain that had parsed of a request or response*/
		vlib_buffer_t *last_parsed_mbuf;
		vlib_buffer_t *next_request;
		vlib_buffer_t *tobesent_mb;
		vlib_buffer_t *body_start_mb;
		char *body_start_pos;
		uint64_t req_start_time;
		CLIB_CACHE_LINE_ALIGN_MARK (pad);
};

int http_parse_request(vlib_buffer_t *mb, unsigned char *data, int data_len, http_parse_data_t *parser_data, unsigned char **processed_data_end_position);
int http_parse_response(unsigned char *data, int data_len, struct dproxy_http_upstream_s *ups, unsigned char **processed_data_end_position);

ngx_int_t myngx_http_init_headers_in_hash(ngx_pool_t *pool);
ngx_int_t myngx_http_init_upstream_headers_in_hash(ngx_pool_t *pool);

#endif /* __DPROXY_HTTP_PARSE_H__*/


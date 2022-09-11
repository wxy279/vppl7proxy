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
 
#ifndef __VPP_HTTP_ERR_DEF_H__
#define __VPP_HTTP_ERR_DEF_H__

#include <bsd/sys/queue.h>
#include <vnet/session/session.h>
#include <vnet/http_proxy/nginx/include/ngx_core.h>
#include <vnet/http_proxy/nginx/include/ngx_http.h>
#include <vnet/http_proxy/my_ngx_http_variables.h>
#include <vnet/http_proxy/http_parse.h>


typedef enum {
    EHTTP_OK            = 0,
    EHTTP_INVAL         = -1,       /* invalid parameter */
    EHTTP_NOMEM         = -2,       /* no memory */
    EHTTP_EXIST         = -3,       /* already exist */
    EHTTP_NOTEXIST      = -4,       /* not exist */
    EHTTP_INVPKT        = -5,       /* invalid packet */
    EHTTP_DROP          = -6,       /* packet dropped */
    EHTTP_NOPROT        = -7,       /* no protocol */
    EHTTP_NOROUTE       = -8,       /* no route */
    EHTTP_DEFRAG        = -9,       /* defragment error */
    EHTTP_FRAG          = -10,      /* fragment error */
    EHTTP_DPDKAPIFAIL   = -11,      /* DPDK error */
    EHTTP_IDLE          = -12,      /* nothing to do */
    EHTTP_BUSY          = -13,      /* resource busy */
    EHTTP_NOTSUPP       = -14,      /* not support */
    EHTTP_RESOURCE      = -15,      /* no resource */
    EHTTP_OVERLOAD      = -16,      /* overloaded */
    EHTTP_NOSERV        = -17,      /* no service */
    EHTTP_DISABLED      = -18,      /* disabled */
    EHTTP_NOROOM        = -19,      /* no room */
    EHTTP_NONEALCORE    = -20,      /* non-eal thread lcore */
    EHTTP_CALLBACKFAIL  = -21,      /* callbacks fail */
    EHTTP_IO            = -22,      /* I/O error */
    EHTTP_MSG_FAIL      = -23,      /* msg callback failed */
    EHTTP_MSG_DROP      = -24,      /* msg callback dropped */
    EHTTP_PKTSTOLEN     = -25,      /* stolen packet */
    EHTTP_SYSCALL       = -26,      /* system call failed */
    EHTTP_NODEV         = -27,      /* no such device */

    /* positive code for non-error */
    EHTTP_KNICONTINUE   = 1,        /* KNI to continue */
    EHTTP_INPROGRESS    = 2,        /* in progress */
} HTTP_ERROR_DEF_e;

#define EHTTP_MBUF_NO_USE EHTTP_OK
#define EHTTP_MBUF_USED EHTTP_PKTSTOLEN

/** these defined in session_types.h
#define RST_APP_ID_HTTP_SERVER		0x0d00
#define RST_APP_ID_HTTP_CLIENT		0x0e00
*/
/*
there some macro definations in http_proxy.h, should merge to here later
#define RST_APP_ID_HTTP         0x0600
#define RST_APP_ID_HTTP2         0x0700
#define RST_APP_ID_HTTP3         0x0800

#define RST_ID_FROM_HTTP_1 (RST_APP_ID_HTTP + 0x1)
#define RST_ID_FROM_HTTP_2 (RST_APP_ID_HTTP + 0x2)
#define RST_ID_FROM_HTTP_3 (RST_APP_ID_HTTP + 0x3)
#define RST_ID_FROM_HTTP_4 (RST_APP_ID_HTTP + 0x4)
#define RST_ID_FROM_HTTP_5 (RST_APP_ID_HTTP + 0x5)
#define RST_ID_FROM_HTTP_6 (RST_APP_ID_HTTP + 0x6)

*/
#define RST_ID_HTTP_CLIENT_0e01  (RST_APP_ID_HTTP_CLIENT + 0x01)
#define RST_ID_HTTP_CLIENT_0e02  (RST_APP_ID_HTTP_CLIENT + 0x02)
#define RST_ID_HTTP_CLIENT_0e03  (RST_APP_ID_HTTP_CLIENT + 0x03)

#define RST_ID_HTTP_SERVER_0d01  (RST_APP_ID_HTTP_SERVER + 0x01)
#define RST_ID_HTTP_SERVER_0d02  (RST_APP_ID_HTTP_SERVER + 0x02)
#define RST_ID_HTTP_SERVER_0d03  (RST_APP_ID_HTTP_SERVER + 0x03)


extern int debug_htp_resp_statem;
#define htp_resp_debug_print(format, args...) do {	\
  if (debug_htp_resp_statem) { 						\
	  clib_warning(format, ## args);				\
  } 												\
} while (0)

extern int debug_htp_req_statem;
#define htp_req_debug_print(format, args...) do {	\
	if (debug_htp_req_statem) {						\
		clib_warning(format, ## args);				\
	}												\
} while (0)

extern int debug_htp_ups_statem;
#define htp_ups_debug_print(format, args...) do {	\
	if (debug_htp_ups_statem) { 					\
		clib_warning(format, ## args);				\
	}												\
} while (0)


extern int debug_htp_pipe_statem;
#define htp_pipe_debug_print(format, args...) do {	\
	if (debug_htp_pipe_statem) { 					\
		clib_warning(format, ## args);				\
	}												\
} while (0)

extern int debug_htp_config_funcs;
#define htp_config_debug_print(format, args...) do {	\
	if (debug_htp_config_funcs) {					\
		clib_warning(format, ## args);				\
	}												\
} while (0)

extern int debug_htp_shipping_funcs;
#define htp_ship_debug_print(format, args...) do {	\
	if (debug_htp_shipping_funcs) {					\
		clib_warning(format, ## args);				\
	}												\
} while (0)


#define EHTTP_MESSAGE_PARSE_COMPLETED        0  // parse body tell body complete
#define EHTTP_MESSAGE_PARSE_CONTINUE         1  // parse body tell body not complete, or nginx tell header or request line not complete
#define EHTTP_MESSAGE_PARSE_ERROR            2  // failed to parse message
#define EHTTP_MESSAGE_PARSE_PARAM_ERROR      3  // parameter wrong

#define EHTTP_REQUEST_LINE_PARSE_COMPLETED   4  // request_line parse completed by nginx
#define EHTTP_HEADER_LINE_PARSE_COMPLETED    5  // header_line (one line) parse completed by nginx
#define EHTTP_HEADER_DONE_PARSE_COMPLETED    6  // header_line (all line) parse completed by nginx
#define EHTTP_HEADER_DONE_NOBY_PARSE_COMPLETED         7  // header_line (all line) parse completed by nginx and content_length = 0

enum ESPIASS_CUR_INPUT_PARSE_RESULT
{
    EHTTP_CUR_INPUT_MESSAGE_PARSE_ERROR = -128,
    EHTTP_CUR_INPUT_PARSED_A_REQ_RES = 0,   /*just finished a request or response parse*/
    EHTTP_CUR_INPUT_MESSAGE_PARSE_INCOMPLETE,
};

/*************************************common defination***************/
#define DP_VS_SERVICE_MAX_REGEX_SERVER 20
typedef struct http_server_regex_map_s
{
		ngx_http_regex_t *regex;
			struct http_server_runtime_s *server;
} http_server_regex_map_t;

#define HTTP_SERVER_NAME_LEN_MAX 64
#define HTTP_SERVER_NAME_MAX	10
#define HTTP_SERVER_REGEX_LOCATION_MAX 16

typedef enum {
	HTTP_UPSTREAM_RR_METHOD     = 0,
	HTTP_UPSTREAM_WRR_METHOD,
	HTTP_UPSTREAM_HIP_METHOD,
	HTTP_UPSTREAM_CHIP_METHOD,
	HTTP_UPSTREAM_MAX_METHOD,
} HTTP_UPSTREAM_METHOD_e;

typedef struct htproxy_real_service_s {
	session_endpoint_t client_sep;
	u8 *client_uri;
	u8 *rs_name;
	HILI_LB_RS_TYPE rs_type;
	HILI_LB_VS_TYPE vs_type;//TODO this should move to the listen conn, then give it to est conn, here just keep inmind
} htproxy_real_service_t;

/*************************************upstream defination***************/
#define HTTP_UPSTREAM_NAME_MAX 64
#define HTTP_UPSTREAM_METHOD_NAME_MAX 16
#define HTTP_UPSTREAM_RS_NUM_MAX 20

typedef struct http_upstream_runtime_s
{
	TAILQ_ENTRY(http_upstream_runtime_s) next_upstream;
	//char husname[HTTP_UPSTREAM_NAME_MAX];
	u8 *husname;
	//char lb_method_name[HTTP_UPSTREAM_METHOD_NAME_MAX];
	u8 *lb_method_name;
	HTTP_UPSTREAM_METHOD_e lb_method;
	u8 rs_num;
	u8 cur_lb_rs;//used for record the current select rs by LB method(for rr case )
	htproxy_real_service_t rs_array[HTTP_UPSTREAM_RS_NUM_MAX];
} http_upstream_runtime_t;

int http_upstream_init(void);
http_upstream_runtime_t *htproxy_get_upstream_rt_conf_by_name(const char *upstream_name);

/*************************************location defination***************/
typedef struct http_location_runtime_s
{
	TAILQ_ENTRY(http_location_runtime_s) next_location;
	ngx_str_t name;/*use to point to loc_uri and orgnize and search in tree*/
	//char loc_uri[HTTP_LOCATION_NAME_MAX];/*used to store the uri configuration*/
	//char hlocname[HTTP_LOCATION_NAME_MAX];
	u8 *loc_uri;
	u8 *hlocname;
	ngx_http_regex_t  *regex;
	unsigned      exact_match:1;
	unsigned      noregex:1;
	unsigned      is_regex:1;
	unsigned      caseless:1;
	struct http_upstream_runtime_s *rt_upstream;
} http_location_runtime_t;

typedef struct {
    ngx_queue_t                      queue;
    http_location_runtime_t         *exact;
    http_location_runtime_t         *inclusive;
    ngx_str_t                       *name;
#if 0
    u_char                          *file_name;
    ngx_uint_t                       line;
#endif
    ngx_queue_t                      list;
} my_ngx_http_location_queue_t;

typedef struct my_ngx_http_location_tree_node_s  my_ngx_http_location_tree_node_t;

struct my_ngx_http_location_tree_node_s {
    my_ngx_http_location_tree_node_t   *left;
    my_ngx_http_location_tree_node_t   *right;
    my_ngx_http_location_tree_node_t   *tree;

    http_location_runtime_t         *exact;
    http_location_runtime_t         *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};

int http_proxy_location_init(void);
http_location_runtime_t *http_get_location_by_name(char *name);

/*************************************server defination***************/
#define HTTP_VIRTUAL_SERVER_NAME_MAX 64

typedef struct http_server_runtime_s
{
	TAILQ_ENTRY(http_server_runtime_s) next_server;
	//char hvsname[HTTP_VIRTUAL_SERVER_NAME_MAX];
	u8 *hvsname;
	//http_location_runtime_t *location;
	ngx_queue_t  *locations;
	my_ngx_http_location_tree_node_t *static_locations;
	http_location_runtime_t *regex_locations[HTTP_SERVER_REGEX_LOCATION_MAX];
	int regex_loc_nb;
	int sn_number;/*number of server_name*/
	char servernames[HTTP_SERVER_NAME_MAX][HTTP_SERVER_NAME_LEN_MAX];
	int sn_regex_number;
	ngx_http_regex_t *regex[HTTP_SERVER_NAME_MAX];
	//struct rte_mempool      *mpool;
	my_ngx_pool_t *ngx_pool;
} http_server_runtime_t;

#define DP_VS_SERVICE_MAX_REGEX_SERVER 20

typedef struct http_server_match_s
{
	ngx_http_virtual_names_t  *virtual_names;
	int regex_server_nb;
	http_server_regex_map_t regex_servers[DP_VS_SERVICE_MAX_REGEX_SERVER];
} http_server_match_t;

ngx_int_t my_ngx_http_core_find_location(ngx_http_request_t *r, http_server_runtime_t *server, http_location_runtime_t **location);
//ngx_int_t my_ngx_http_core_find_static_location(ngx_http_request_t *r, my_ngx_http_location_tree_node_t *node);
ngx_int_t myngx_http_process_host(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset, struct http_parse_data_s *hdata);

int htproxy_server_init(void);
int htproxy_upstream_init(void);
int htproxy_location_init(void);
/**********************************other defination********************/

typedef TAILQ_HEAD(runtime_server_config_tq_head, http_server_runtime_s) runtime_server_config_tq;
extern runtime_server_config_tq rt_server_conf_tq;

typedef TAILQ_HEAD(runtime_upstream_config_tq_head, http_upstream_runtime_s) runtime_upstream_config_tq;
extern runtime_upstream_config_tq rt_upstream_conf_tq;

typedef TAILQ_HEAD(runtime_location_config_tq_head, http_location_runtime_s) runtime_location_config_tq;
extern runtime_location_config_tq rt_location_conf_tq;

#endif /*__VPP_HTTP_ERR_DEF_H__*/

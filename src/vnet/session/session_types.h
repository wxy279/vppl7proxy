/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
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

#ifndef SRC_VNET_SESSION_SESSION_TYPES_H_
#define SRC_VNET_SESSION_SESSION_TYPES_H_

#include <svm/svm_fifo.h>
#include <vnet/session/transport_types.h>
#include <vnet/session/session_timer_queue.h>


//#include <vnet/http_proxy/nginx/include/ngx_queue.h>

/*add for http proxy*/
#include <pthread.h>
/**
 * Macro to define a per lcore variable "var" of type "type", don't
 * use keywords like "static" or "volatile" in type, just prefix the
 * whole macro.
 */
#define RTE_DEFINE_PER_LCORE(type, name)			\
	__thread __typeof__(type) per_lcore_##name

/**
 * Macro to declare an extern per lcore variable "var" of type "type"
 */
#define RTE_DECLARE_PER_LCORE(type, name)			\
	extern __thread __typeof__(type) per_lcore_##name

/**
 * Read/write the per-lcore variable value
 */
#define RTE_PER_LCORE(name) (per_lcore_##name)


#define ONE_SEGMENT_MAX_LEN (2048 - 64)

/*end for http proxy*/

//#define func_trace 1

#define ft_printf(format, args...) do {        \
   if (0) {                       \
   	   printf("%s:%d\n",__func__,__LINE__);    \
       printf(format, ## args);            \
   }                                       \
} while (0)

#define FT_PRINTF(label, buf, len) do { \
   if (0) {               \
      uint32_t iofcgw;                                 \
      printf("%s. %s [%d bytes]:\n", __FUNCTION__, (label), (len));        \
      for (iofcgw = 0; iofcgw < (uint32_t)(len); iofcgw++) {\
         printf("0x%02x%s", (buf)[iofcgw],  (iofcgw % 8 == 7) ? "\n" : ", ");  \
      }\
      printf("\n"); \
   }               \
} while (0)

#define TLS_PRINTF(label, buf, len) do { \
		 if (1) {				\
			uint32_t iofcgw;								 \
			printf("%s. %s [%d bytes]:\n", __FUNCTION__, (label), (len));		 \
			for (iofcgw = 0; iofcgw < (uint32_t)(len); iofcgw++) {\
			   printf("0x%02x%s", (buf)[iofcgw],  (iofcgw % 8 == 7) ? "\n" : ", ");  \
			}\
			printf("\n"); \
		 }				 \
} while (0)


#define FUNC_TRACE do { \
   if (1) {                       \
       session_log_debug("Enter function %s\n",__func__);    \
   }							 \
} while (0)

#define LINE_TRACE do {											\
   if (1) {														\
		session_log_debug("Come %s:%d\n",__func__,__LINE__);	\
   }															\
} while (0)


extern int debug_session_node;
#define session_node_print(format, args...) do {	  \
	if (debug_session_node) {					  	  \
		clib_warning(format, ## args);				  \
	}												  \
} while (0)

extern int debug_session_exchange;
#define session_exchange_print(format, args...) do {\
  if (debug_session_exchange) {						\
	  clib_warning(format, ## args);				\
  } 									  			\
} while (0)

#define DEBUG_DUMP_SESSION_VLIB_BUFFER(label, p) do { \
  if (debug_session_exchange) {						  \
	  clib_warning("%s:",(label));					  \
	  clib_warning("%U", format_vnet_buffer, (p));	  \
  } 												  \
} while (0)

extern int debug_tcp_reass;
#define tcp_reass_print(format, args...) do {			\
	if (debug_tcp_reass) {					  			\
		clib_warning(format, ## args);				  	\
	}												  	\
} while (0)

#define DEBUG_DUMP_TCP_REASS_VLIB_BUFFER(label, p) do { \
	if (debug_tcp_reass) {								\
		clib_warning("%s:",(label));					\
		clib_warning("%U", format_vnet_buffer, (p));	\
	}													\
} while (0)


#define SESSION_FUNC_TRACE do { 		\
 if (debug_session_exchange) {			\
	 clib_warning("Enter function");	\
 }							   			\
} while (0)

#define SESSION_LINE_TRACE do { 	\
	if (debug_session_exchange) {	\
		 clib_warning("Come here");	\
	}							 	\
} while (0)

#define hili_print(format, args...) do {			\
	clib_warning(format, ## args);					\
} while (0)

#define hili_buffer_trace_print(vb) do {			\
	if ((vb)->flags & VNET_BUFFER_F_HILI_TRACE) {	\
		clib_warning("Trace buffer come here");		\
	}												\
} while (0)

#define hili_buffer_set_trace_flag(vb) do {			\
		(vb)->flags |= VNET_BUFFER_F_HILI_TRACE;	\
		hili_buffer_trace_print(vb);				\
} while (0)


/*netfe_stream type*/
#define SS_PIPE 0X01
#define SS_TCP  0x02
/*netfe_stream flags  64bit*/

#define SS_TCP_AS_CLIENT				 0x01
#define SS_TCP_AS_SERVER				 0x02
#define SS_TCP_AS_CLIENT_TMP			 0x04
#define SS_TCP_RESET					 0x08    /*TCP receive rst*/

#define SS_TCP_RECV_FISRT_FIN		 	 0x10    /*Passive recv fin, close issued by peer*/
#define SS_TCP_UNUSE4					 0x20    /*unused*/
#define SS_TCP_UNUSE5					 0x40	 /*unused*/
#define SS_TCP_RECV_SECOND_FIN		 	 0x80	 /*recv second FIN, close issued by itself*/

#define SS_TCP_UNUSE6					 0x100

#define SS_TCP_CLOSE_WAIT_TOO_LONG		 0x1000
#define SS_TCP_F1_TOO_LONG		 		 0x2000
#define SS_TCP_F1_NO_RESP_TOO_LONG		 0x4000

/*falgs for HTTP proxy*/
#define DPROXY_HTTP_KEEPALIVE		 0x8000

/*NFS_TCP MAX FLAG 0x200000*/
									     /*bit 23*/
#define SS_TCP_APPCLOSE    			 	 	0x400000
#define SS_TCP_APPBREAKUP				 	0x800000
#define SS_TCP_APPTERM					 	0x1000000
#define SS_TCP_APPWRITE 					0x2000000
#define SS_TCP_APPNOWINDOW					0x4000000
/*NFS_APP MAX FLAG 					     	0x800000000*/

										/*bit 37*/
#define SS_PIPE_UNUSE1					0x1000000000
#define SS_PIPE_UNUSE2					0x2000000000
#define SS_PIPE_UNUSE3					0x4000000000

#define SS_TCP_APP_CTRL_FLAG	(SS_TCP_RESET | SS_TCP_RECV_FISRT_FIN | SS_TCP_RECV_SECOND_FIN | SS_TCP_APPCLOSE | SS_TCP_APPTERM)

#define HILI_OPEN_SESION_APP_ID 	0xdeadbeef
#define HILI_SESSION_APP_ID			0xdeadc0de

/*
 * Pipe session states
 */
typedef enum
{
	SESSION_PIPE_STATE_CREATING, 		/*刚�?�过pipe_open创建的远端pipe*/
	SESSION_PIPE_STATE_EST, 			/*estabilish, local在pipe_open进入状�??, CREATING 处理后进入此状�??*/
	SESSION_PIPE_STATE_CLOSING,			/*代表�?half close, 被hili_session_pipe_halfclose设置*/
	SESSION_PIPE_STATE_TERM,			/*hili_session_pipe_terminate设置，代表可以被删除*/
	SESSION_PIPE_STATE_N_STATES,
} hili_pipe_session_state_t;


/*netfe_stream flags end*/

#define RST_APP_ID_SSL			0x0200
#define RST_APP_ID_SSL_RECORD		0x0a00
#define RST_APP_ID_SSL_SERVER		0x0b00
#define RST_APP_ID_SSL_CLIENT		0x0c00

#define RST_APP_ID_HTTP_SERVER		0x0d00
#define RST_APP_ID_HTTP_CLIENT		0x0e00


/*define for cons_side_type */

#define SESSION_CONSUME_TYPE	1
#define TLSP_CONSUME_TYPE		2

#if 0
typedef int (*active_open_handle_func_t)(session_t *hili_ss, u32 tp_cons_index, u32 tid, u8 is_fail);

typedef struct _tlsproxy_cons_t
{
	u8  cons_side_type;  /*SESSION_CONSUME_TYPE or TLSP_CONSUME_TYPE*/
	u8  thread_index;
	/*record consume side session index*/
	u32 cons_side_index;
	/*record the tmp setup session, which will free when tcp connection establihsed*/
	u32 tmp_session_index;
	/** tlsproxy_cons_t index in per_thread pool */
	u32 tlsproxy_cons_index;

	CLIB_CACHE_LINE_ALIGN_MARK (pad);
} tlsproxy_cons_t;
#endif

/*define for hili_extflags */
#define SS_EXTFLAG_TLSPROXY	0x01

/* Modulo arithmetic for TCP sequence numbers copy from tcp.h*/
#define seq_lt(_s1, _s2) ((i32)((_s1)-(_s2)) < 0)
#define seq_leq(_s1, _s2) ((i32)((_s1)-(_s2)) <= 0)
#define seq_gt(_s1, _s2) ((i32)((_s1)-(_s2)) > 0)
#define seq_geq(_s1, _s2) ((i32)((_s1)-(_s2)) >= 0)
#define seq_max(_s1, _s2) (seq_gt((_s1), (_s2)) ? (_s1) : (_s2))


#define SESSION_LISTENER_PREFIX		0x5FFFFFFF

#define foreach_session_endpoint_fields				\
  foreach_transport_endpoint_cfg_fields				\
  _(u8, transport_proto)					\

typedef struct _session_endpoint
{
#define _(type, name) type name;
  foreach_session_endpoint_fields
#undef _
} session_endpoint_t;

typedef struct _session_endpoint_cfg
{
#define _(type, name) type name;
  foreach_session_endpoint_fields
#undef _
  u32 app_wrk_index;
  u32 opaque;
  u32 ns_index;
  u8 original_tp;
  u8 *hostname;
} session_endpoint_cfg_t;

#define SESSION_IP46_ZERO			\
{						\
    .ip6 = {					\
	{ 0, 0, },				\
    },						\
}

#define TRANSPORT_ENDPOINT_NULL			\
{						\
  .sw_if_index = ENDPOINT_INVALID_INDEX,	\
  .ip = SESSION_IP46_ZERO,			\
  .fib_index = ENDPOINT_INVALID_INDEX,		\
  .is_ip4 = 0,					\
  .port = 0,					\
}
#define SESSION_ENDPOINT_NULL 			\
{						\
  .sw_if_index = ENDPOINT_INVALID_INDEX,	\
  .ip = SESSION_IP46_ZERO,			\
  .fib_index = ENDPOINT_INVALID_INDEX,		\
  .is_ip4 = 0,					\
  .port = 0,					\
  .peer = TRANSPORT_ENDPOINT_NULL,		\
  .transport_proto = 0,				\
}
#define SESSION_ENDPOINT_CFG_NULL 		\
{						\
  .sw_if_index = ENDPOINT_INVALID_INDEX,	\
  .ip = SESSION_IP46_ZERO,			\
  .fib_index = ENDPOINT_INVALID_INDEX,		\
  .is_ip4 = 0,					\
  .port = 0,					\
  .peer = TRANSPORT_ENDPOINT_NULL,		\
  .transport_proto = 0,				\
  .app_wrk_index = ENDPOINT_INVALID_INDEX,	\
  .opaque = ENDPOINT_INVALID_INDEX,		\
  .hostname = 0,				\
}

#define session_endpoint_to_transport(_sep) ((transport_endpoint_t *)_sep)
#define session_endpoint_to_transport_cfg(_sep)		\
  ((transport_endpoint_cfg_t *)_sep)

always_inline u8
session_endpoint_fib_proto (session_endpoint_t * sep)
{
  return sep->is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
}

static inline u8
session_endpoint_is_local (session_endpoint_t * sep)
{
  return (ip_is_zero (&sep->ip, sep->is_ip4)
	  || ip_is_local_host (&sep->ip, sep->is_ip4));
}

static inline u8
session_endpoint_is_zero (session_endpoint_t * sep)
{
  return ip_is_zero (&sep->ip, sep->is_ip4);
}

typedef u8 session_type_t;
typedef u64 session_handle_t;

/*
 * Session states
 */
typedef enum
{
  SESSION_STATE_CREATED, 			/*#0 监听状�?�下收到了主动建联的SYN 就设置为该状�?*/
  SESSION_STATE_LISTENING,			/*#1 s*/
  SESSION_STATE_CONNECTING, 		/*#2 主动建联时，收到了对端的SYN|ACK后设置为该状�?*/
  SESSION_STATE_ACCEPTING, 			/*#3 被动建联，收到了第三个ACK,设置为该状�??*/
  SESSION_STATE_READY,				/*#4 或主动建联，或被动建联，当完成建联且通知了session�?,设置为该状�??*/
  SESSION_STATE_OPENED,     		/*#5 cl类型主动建联�?,设置为该状�??*/

  SESSION_STATE_TRANSPORT_CLOSING,  /*#6 EST状�?�下，TCP层收到了第一个FIN或�?�是收到了RST�?,设置为该状�??,代表被动关闭*/
  SESSION_STATE_CLOSING,			/*#7 上层app调用session_close关闭,设置为该状�??*/
  SESSION_STATE_CLOSED_WAITING,		/*#8 (session_close触发的事�?)在session node处理调用session_transport_close发现有数据要�?,设置为该状�??*/
  SESSION_STATE_TRANSPORT_CLOSED,	/*#9 该状态代表传输层连接结构已经被干掉时,设置为该状�?�，告诉session 自己保重*/
  									/*该状态的赋�?�只在session_transport_closed_notify �? session_transport_delete_notify,意味�?tcp不复存在*/
  SESSION_STATE_CLOSED,				/*#10 该状态在close notify和session node 处理close时设置为该状态，代表可以被删�?*/
  SESSION_STATE_N_STATES,
} session_state_t;

typedef enum session_flags_
{
  SESSION_F_RX_EVT = 1,
  SESSION_F_PROXY = (1 << 1),
} session_flags_t;

typedef struct session_
{
  /** Pointers to rx/tx buffers. Once allocated, these do not move */
  svm_fifo_t *rx_fifo;
  svm_fifo_t *tx_fifo;

  /** Type built from transport and network protocol types */
  session_type_t session_type;

  /** State in session layer state machine. See @ref session_state_t */
  volatile u8 session_state;

  /** Index in thread pool where session was allocated */
  u32 session_index;

  /** Index of the app worker that owns the session */
  u32 app_wrk_index;

  /** Index of the thread that allocated the session */
  u8 thread_index;

  /** Session flags. See @ref session_flags_t */
  u32 flags;

  /** Index of the transport connection associated to the session */
  u32 connection_index;

  /** Index of application that owns the listener. Set only if a listener */
  u32 app_index;


  /*Start hili add ==========*/
  uint32_t	 hili_type;
  uint16_t reset_errorcode;
  uint64_t	 hili_flags;
  uint64_t	 hili_extflags;
  int (*rx_cb_func)(struct session_ *);	  /* application handler */ 
  void *cons_side;
  struct session_ *fwds;

  /** State in session pipe layer state machine. See @ref hili_pipe_session_state_t */
  volatile u8 hili_pipe_session_state;
  u8 				cur_state_id;
  session_state_t  ss_state_array[SESSION_STATE_N_STATES];

  uint32_t sendenddata; /* init to 0 */
  uint32_t sendrightwin; /* init to netfe_pipe_max_buffer */

  unsigned write:1;//TODO write and read there no place assign value to them
  unsigned read:1;

  void (*clenup_cb_func)(struct session_ *);//give the app chance to do the cleanup, introduced by http proxy to relase resource

  vlib_buffer_t	*recv_head_b;
  vlib_buffer_t	*recv_tail_b;

  vlib_buffer_t	*send_head_b;
  vlib_buffer_t	*send_tail_b;

  vlib_buffer_t	*reass_head_b;
  vlib_buffer_t	*reass_tail_b;

  vlib_buffer_t 	*next_tbs_buffer;
  void *conn_rs;
  struct http_parse_data_s *http_data;
  u32 next_tbs_buffer_off;
  my_ngx_queue_t keepalive_queue;
  TAILQ_ENTRY(session_) session_ue;		        /* app event queue entry*/
  TAILQ_ENTRY(session_) session_hclosee;		 	/* tcp half close event queue entry*/
  TAILQ_ENTRY(session_) session_terme;				/* tcp terminate event queue entry*/
  TAILQ_ENTRY(session_) session_txe;				/* tcp transimit event queue entry*/
  TAILQ_ENTRY(session_) session_ptxe;				/* tcp transimit pending event queue entry*/

  TAILQ_ENTRY(session_) ss_pipe_ue;		        /* pipe event queue entry */
  TAILQ_ENTRY(session_) ss_pipe_de;				/* pipe delete event queue entry*/

  /*End hili add===============*/

  union
  {
    /** Parent listener session index if the result of an accept */
    u32 listener_index;

    /** App listener index in app's listener pool if a listener */
    u32 al_index;
  };

  /** Opaque, for general use */
  u32 opaque;

    CLIB_CACHE_LINE_ALIGN_MARK (pad);
} session_t;

typedef int (*active_open_handle_func_t)(session_t *hili_ss, u32 tp_cons_index, u32 tid, u8 is_fail);

typedef struct _tlsproxy_cons_t
{
	u8  cons_side_type;  /*SESSION_CONSUME_TYPE or TLSP_CONSUME_TYPE*/
	u8  thread_index;
	/*record consume side session index*/
	u32 cons_side_index;
	/*record the tmp setup session, which will free when tcp connection establihsed*/
	u32 tmp_session_index;
	/** tlsproxy_cons_t index in per_thread pool */
	u32 tlsproxy_cons_index;
	active_open_handle_func_t act_open_cb_func;
	CLIB_CACHE_LINE_ALIGN_MARK (pad);
} tlsproxy_cons_t;


always_inline session_type_t
session_type_from_proto_and_ip (transport_proto_t proto, u8 is_ip4)
{
  return (proto << 1 | is_ip4);
}

always_inline transport_proto_t
session_type_transport_proto (session_type_t st)
{
  return (st >> 1);
}

always_inline u8
session_type_is_ip4 (session_type_t st)
{
  return (st & 1);
}

always_inline transport_proto_t
session_get_transport_proto (session_t * s)
{
  return (s->session_type >> 1);
}

always_inline fib_protocol_t
session_get_fib_proto (session_t * s)
{
  u8 is_ip4 = s->session_type & 1;
  return (is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);
}

always_inline u8
session_has_transport (session_t * s)
{
  return (session_get_transport_proto (s) != TRANSPORT_PROTO_NONE);
}

static inline transport_service_type_t
session_transport_service_type (session_t * s)
{
  transport_proto_t tp;
  tp = session_get_transport_proto (s);
  return transport_protocol_service_type (tp);
}

static inline transport_tx_fn_type_t
session_transport_tx_fn_type (session_t * s)
{
  transport_proto_t tp;
  tp = session_get_transport_proto (s);
  return transport_protocol_tx_fn_type (tp);
}

static inline u8
session_tx_is_dgram (session_t * s)
{
  return (session_transport_tx_fn_type (s) == TRANSPORT_TX_DGRAM);
}

always_inline session_handle_t
session_handle (session_t * s)
{
  return ((u64) s->thread_index << 32) | (u64) s->session_index;
}

always_inline u32
session_index_from_handle (session_handle_t handle)
{
  return handle & 0xFFFFFFFF;
}

always_inline u32
session_thread_from_handle (session_handle_t handle)
{
  return handle >> 32;
}

always_inline void
session_parse_handle (session_handle_t handle, u32 * index,
		      u32 * thread_index)
{
  *index = session_index_from_handle (handle);
  *thread_index = session_thread_from_handle (handle);
}

typedef enum
{
  SESSION_IO_EVT_RX,
  SESSION_IO_EVT_TX,
  SESSION_IO_EVT_TX_FLUSH,
  SESSION_IO_EVT_BUILTIN_RX,
  SESSION_IO_EVT_BUILTIN_TX,
  SESSION_CTRL_EVT_RPC,
  SESSION_CTRL_EVT_CLOSE,
  SESSION_CTRL_EVT_BOUND,
  SESSION_CTRL_EVT_UNLISTEN_REPLY,
  SESSION_CTRL_EVT_ACCEPTED,
  SESSION_CTRL_EVT_ACCEPTED_REPLY,
  SESSION_CTRL_EVT_CONNECTED,
  SESSION_CTRL_EVT_CONNECTED_REPLY,
  SESSION_CTRL_EVT_DISCONNECTED,
  SESSION_CTRL_EVT_DISCONNECTED_REPLY,
  SESSION_CTRL_EVT_RESET,
  SESSION_CTRL_EVT_RESET_REPLY,
  SESSION_CTRL_EVT_REQ_WORKER_UPDATE,
  SESSION_CTRL_EVT_WORKER_UPDATE,
  SESSION_CTRL_EVT_WORKER_UPDATE_REPLY,  
} session_evt_type_t;

/* Deprecated and will be removed. Use types above */
#define FIFO_EVENT_APP_RX SESSION_IO_EVT_RX
#define FIFO_EVENT_APP_TX SESSION_IO_EVT_TX
#define FIFO_EVENT_DISCONNECT SESSION_CTRL_EVT_CLOSE
#define FIFO_EVENT_BUILTIN_RX SESSION_IO_EVT_BUILTIN_RX
#define FIFO_EVENT_BUILTIN_TX SESSION_IO_EVT_BUILTIN_TX

typedef enum
{
  SESSION_MQ_IO_EVT_RING,
  SESSION_MQ_CTRL_EVT_RING,
  SESSION_MQ_N_RINGS
} session_mq_rings_e;

typedef struct
{
  void *fp;
  void *arg;
} session_rpc_args_t;

typedef struct
{
  u8 event_type;
  u8 postponed;
  union
  {
    u32 session_index;
    session_handle_t session_handle;
    session_rpc_args_t rpc_args;
    struct
    {
      u8 data[0];
    };
  };
} __clib_packed session_event_t;

#define SESSION_MSG_NULL { }

typedef struct session_dgram_pre_hdr_
{
  u32 data_length;
  u32 data_offset;
} session_dgram_pre_hdr_t;

typedef struct session_dgram_header_
{
  u32 data_length;
  u32 data_offset;
  ip46_address_t rmt_ip;
  ip46_address_t lcl_ip;
  u16 rmt_port;
  u16 lcl_port;
  u8 is_ip4;
} __clib_packed session_dgram_hdr_t;

#define SESSION_CONN_ID_LEN 37
#define SESSION_CONN_HDR_LEN 45

STATIC_ASSERT (sizeof (session_dgram_hdr_t) == (SESSION_CONN_ID_LEN + 8),
	       "session conn id wrong length");
#endif /* SRC_VNET_SESSION_SESSION_TYPES_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

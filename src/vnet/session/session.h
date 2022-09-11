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
#ifndef __included_session_h__
#define __included_session_h__

#include <vnet/session/session_types.h>
#include <vnet/session/session_lookup.h>
#include <vnet/session/session_debug.h>
#include <vnet/session/session_timer_queue.h>
#include <svm/message_queue.h>
#include <svm/ssvm.h>


/*
 * Returns an mbuf chain long enough to hold len bytes of data, left justified.
 */

#define MAX_PER_SEG 1448
#define STACK_MBUF_BUF_SIZE	2048   /*elm size of stack_mpool*/


/* For app Event Queue */
typedef TAILQ_HEAD(stream_session_ue_head, session_) stream_session_ue_head_t;

/* For Stack Event Queue */
typedef TAILQ_HEAD(stream_session_se_head, session_) stream_session_se_head_t;

/* For User Event Queue of non-ip-pcbs */
typedef TAILQ_HEAD(stream_session_pipe_ue_head, session_) stream_session_pipe_ue_head_t;

/* For pipe deletes */
typedef TAILQ_HEAD(stream_session_dq_head, session_) stream_session_dq_head_t;

/**
 * refer to Default fifo and segment size 1<< 12. TODO config.
 * here set to 32 * 1024 
 */
static u32 default_txrx_buffer_size = 32 * 1024;

extern int hili_proxy_enabled;
always_inline int 
is_stream_session_hili_proxy_enable(void)
{
	return hili_proxy_enabled;
}

/* logging */
#define session_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, session_main.log_class, __VA_ARGS__)
#define session_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, session_main.log_class, __VA_ARGS__)
#define session_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, session_main.log_class, __VA_ARGS__)
#define session_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, session_main.log_class, __VA_ARGS__)
#define session_log_debug(...)\
  vlib_log(VLIB_LOG_LEVEL_DEBUG, session_main.log_class, __VA_ARGS__)

typedef enum
{
	HILI_LB_TCP_RS = 100,
	HILI_LB_TLS_RS
} HILI_LB_RS_TYPE;

typedef enum
{
	HILI_LB_TCP_VS = 200,
	HILI_LB_TLS_VS
} HILI_LB_VS_TYPE;

typedef enum
{
	LB_METHOD_RR = 300,
	LB_METHOD_HI
} HILI_LB_METHOD_TYPE;

typedef enum {
	HILI_SESSION_CUR_BREAKUP = -1,
	HILI_SESSION_CUR_STABLE  = 0,
	HILI_SESSION_CUR_CLOSING = 1,
} session_cur_status_t;

typedef enum
{
	WAITCLOSE_TIMEO_REASON_CLOSE_WAIT_TOO_LONG,
	WAITCLOSE_TIMEO_REASON_FIN_WAIT_1_TOO_LONG,
	WAITCLOSE_TIMEO_REASON_FIN_WAIT_1_NO_RESPONSE,
	WAITCLOSE_TIMEO_REASON_LAST_ACK_AND_CLOSING,
	WAITCLOSE_TIMEO_REASON_NON_EST_RESET_COMING,
	WAITCLOSE_TIMEO_REASON_MAX,
} hili_tcp_waitclose_timeo_reason_t;


typedef struct
{
	session_endpoint_t server_sep;
	session_endpoint_t client_sep;
	u8 *server_uri;
	u8 *client_uri;
	u8 *lb_name;
	void *app_config;
	void *lb_server_stack_data;
	void *lb_client_stack_data;
	HILI_LB_RS_TYPE rs_type;
	HILI_LB_VS_TYPE vs_type;
	HILI_LB_METHOD_TYPE lb_method;
	u8   thread_index;
	u16  hili_config_flags;
	/* index in per_thread pool */
	u32 hili_lb_config_index;
	/* Maybe can be used later*/
	u32 opaque;

	CLIB_CACHE_LINE_ALIGN_MARK (pad);
} hili_lb_config_t;

typedef struct _hili_lb_config_main_t
{
	/** Per worker thread tls conn pools */
	hili_lb_config_t **hili_lb_config_pools;
	/** Per worker-thread tls connection pool peekers rw locks */
	clib_rwlock_t *hili_lb_config_peekers_rw_locks;

	u8 is_enabled;
	HILI_LB_METHOD_TYPE default_lb_method;
	/** Preallocate session config parameter */
	u32 preallocated_lb_config;
} hili_lb_config_main_t;

extern hili_lb_config_main_t hili_lb_config_main;
extern hili_lb_config_t tlsproxy_main;

/*tls data functions declare*/
always_inline u8
hili_lb_config_is_valid(u32 si, u8 thread_index)
{
	hili_lb_config_t *s;
	s = pool_elt_at_index (hili_lb_config_main.hili_lb_config_pools[thread_index], si);
	if (s->thread_index != thread_index || s->hili_lb_config_index != si) {
		ft_printf("s->thread_index != thread_index || s->hili_lb_config_index != si and return 0\n");
		return 0;
	}
	return 1;
}

always_inline hili_lb_config_t *
hili_lb_config_get (u32 si, u32 thread_index)
{
	ASSERT (hili_lb_config_is_valid (si, thread_index));
	return pool_elt_at_index (hili_lb_config_main.hili_lb_config_pools[thread_index], si);
}

always_inline hili_lb_config_t *
hili_lb_config_get_if_valid (u64 si, u32 thread_index)
{
	if (thread_index >= vec_len (hili_lb_config_main.hili_lb_config_pools)) {
		ft_printf("thread_index >= vec_len (hili_lb_config_main.hili_lb_config_pools), return NULL\n");
		return 0;
	}

	if (pool_is_free_index (hili_lb_config_main.hili_lb_config_pools[thread_index], si)) {
		ft_printf("there is no item, return NULL\n");
		return 0;
	}
	ASSERT (hili_lb_config_is_valid (si, thread_index));
	return pool_elt_at_index (hili_lb_config_main.hili_lb_config_pools[thread_index], si);

}

hili_lb_config_t * hili_lb_config_alloc(u32 thread_index);

hili_lb_config_t * hili_get_lb_config_by_name(char *name);

void hili_lb_config_free(hili_lb_config_t * s);

int tp_parse_uri (char *uri, session_endpoint_t * sep);


typedef enum
{
	TQ_TYPE_TCP_TOUCH_APP,
	TQ_TYPE_PIPE_TOUCH_APP,
	TQ_TYPE_TCP_CTRL_HALF_CLOSE,
	TQ_TYPE_TCP_CTRL_TERMINATE,
	TQ_TYPE_TCP_CTRL_TX,
	TQ_TYPE_PIPE_DEL,
} hili_tq_type_t;


typedef enum
{
	TX_BUFFER,
	RX_BUFFER,
} txrx_buffer_type_t;


#define foreach_session_input_error                                    	\
_(NO_SESSION, "No session drops")                                       \
_(NO_LISTENER, "No listener for dst port drops")                        \
_(ENQUEUED, "Packets pushed into rx fifo")                              \
_(NOT_READY, "Session not ready packets")                               \
_(FIFO_FULL, "Packets dropped for lack of rx fifo space")               \
_(EVENT_FIFO_FULL, "Events not sent for lack of event fifo space")      \
_(API_QUEUE_FULL, "Sessions not created for lack of API queue space")   \
_(NEW_SEG_NO_SPACE, "Created segment, couldn't allocate a fifo pair")   \
_(NO_SPACE, "Couldn't allocate a fifo pair")				\
_(SEG_CREATE, "Couldn't create a new segment")

typedef enum
{
#define _(sym,str) SESSION_ERROR_##sym,
  foreach_session_input_error
#undef _
    SESSION_N_ERROR,
} session_error_t;

typedef struct session_tx_context_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  session_t *s;
  transport_proto_vft_t *transport_vft;
  transport_connection_t *tc;
  u32 max_dequeue;		/*从tx_offset �?始到可发送队列末尾共可以发�?�的数据*/
  u32 snd_space;
  u32 left_to_snd;
  u32 tx_offset;		/*从可发�?�队列的第一个byte算起，要发�?�的数据的偏�?*/
  u32 max_len_to_snd;	/*通过窗口和在队列中实际可发�?�的数据得出本次要发送的数据长度*/
  u16 deq_per_first_buf; /*第一个包中有100字节头部空间要�?�虑*/
  u16 deq_per_buf;	/*min (ctx->snd_mss, n_bytes_per_buf)，意为每次从fifo取多长的数据来填充一个buffer*/
  u16 snd_mss;
  u16 n_segs_per_evt;	/*max_len_to_snd/snd_mss,how many seg needed to take outgoing data*/
  u8 n_bufs_per_seg;	/*(MAX_HDRS_LEN + ctx->snd_mss ) / n_bytes_per_buf, normally(1460 snd_mss) it's 1 */
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  session_dgram_hdr_t hdr;
} session_tx_context_t;

typedef struct session_worker_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** Worker session pool */
  session_t *sessions;

  /** vpp event message queue for worker */
  svm_msg_q_t *vpp_event_queue;

  /** Our approximation of a "complete" dispatch loop period */
  f64 dispatch_period;

  /** vlib_time_now last time around the track */
  f64 last_vlib_time;

  /** Per-proto vector of sessions to enqueue */
  u32 *session_to_enqueue[TRANSPORT_N_PROTO];

  /** Context for session tx */
  session_tx_context_t ctx;

  /** Vector of tx buffer free lists */
  u32 *tx_buffers;

  /** Vector of partially read events */
  session_event_t *free_event_vector;

  /** Vector of active event vectors */
  session_event_t *pending_event_vector;

  /** Vector of postponed disconnects */
  session_event_t *pending_disconnects;

  /** Vector of postponed events */
  session_event_t *postponed_event_vector;

  /** Peekers rw lock */
  clib_rwlock_t peekers_rw_locks;

  u32 last_tx_packets;
  /** session app handle tailq */
  stream_session_ue_head_t   	session_ue_queue;
  stream_session_se_head_t	 	session_hclosee_queue;
  stream_session_se_head_t	 	session_terme_queue;
  stream_session_se_head_t	 	session_txe_queue;
  stream_session_se_head_t	 	session_ptxe_queue;			/*tx event pending queue, all the actural tx event is process in txe_queue*/
  stream_session_pipe_ue_head_t session_pipe_ue_queue;
  stream_session_dq_head_t   	session_pipe_de_queue;

  /* tlsproxy half open case need to rechain the consumer side*/
  /* Per work-thread tlsproxy_cons_t pool*/
  tlsproxy_cons_t *tlscons;
  /** Per worker-thread tlsproxy_cons_t peekers rw locks */
  clib_rwlock_t tlscons_peekers_rw_locks;

} session_worker_t;

typedef int (session_fifo_rx_fn) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  session_worker_t * wrk,
				  session_event_t * e, int *n_tx_pkts);

extern session_fifo_rx_fn session_tx_fifo_peek_and_snd;
extern session_fifo_rx_fn session_tx_fifo_dequeue_and_snd;
extern session_fifo_rx_fn session_tx_fifo_dequeue_internal;

u8 session_node_lookup_fifo_event (svm_fifo_t * f, session_event_t * e);

typedef struct session_main_
{
  /** Worker contexts */
  session_worker_t *wrk;

  /** Event queues memfd segment initialized only if so configured */
  ssvm_private_t evt_qs_segment;

  /** Unique segment name counter */
  u32 unique_segment_name_counter;

  /** Per transport rx function that can either dequeue or peek */
  session_fifo_rx_fn **session_tx_fns;

  /** Per session type output nodes. Could optimize to group nodes by
   * fib but lookup would then require session type parsing in session node.
   * Trade memory for speed, for now */
  u32 *session_type_to_next;

  /*
   * Config parameters
   */

  /** Session manager is enabled */
  u8 is_enabled;

  /** vpp fifo event queue configured length */
  u32 configured_event_queue_length;

  /** Session ssvm segment configs*/
  uword session_baseva;
  uword session_va_space_size;
  uword evt_qs_segment_size;
  u8 evt_qs_use_memfd_seg;

  /** Session table size parameters */
  u32 configured_v4_session_table_buckets;
  u32 configured_v4_session_table_memory;
  u32 configured_v4_halfopen_table_buckets;
  u32 configured_v4_halfopen_table_memory;
  u32 configured_v6_session_table_buckets;
  u32 configured_v6_session_table_memory;
  u32 configured_v6_halfopen_table_buckets;
  u32 configured_v6_halfopen_table_memory;

  /** Transport table (preallocation) size parameters */
  u32 local_endpoints_table_memory;
  u32 local_endpoints_table_buckets;

  /** Preallocate session config parameter */
  u32 preallocated_sessions;

  /* log class */
  vlib_log_class_t log_class;

#if SESSION_DEBUG
  /**
   * last event poll time by thread
   * Debug only. Will cause false cache-line sharing as-is
   */
  f64 *last_event_poll_by_thread;
#endif

} session_main_t;

extern session_main_t session_main;
extern vlib_node_registration_t session_queue_node;
extern vlib_node_registration_t session_queue_process_node;
extern vlib_node_registration_t session_queue_pre_input_node;

#define SESSION_Q_PROCESS_FLUSH_FRAMES	1
#define SESSION_Q_PROCESS_STOP		2

always_inline u8
session_is_valid (u32 si, u8 thread_index)
{
  session_t *s;
  s = pool_elt_at_index (session_main.wrk[thread_index].sessions, si);
  if (s->session_state == SESSION_STATE_CLOSED)
    return 1;

  if (s->thread_index != thread_index || s->session_index != si)
    return 0;
  return 1;
}

session_t *session_alloc (u32 thread_index);
void session_free (session_t * s);
void session_free_w_fifos (session_t * s);

always_inline session_t *
session_get (u32 si, u32 thread_index)
{
  ASSERT (session_is_valid (si, thread_index));
  return pool_elt_at_index (session_main.wrk[thread_index].sessions, si);
}

always_inline session_t *
session_get_if_valid (u64 si, u32 thread_index)
{
  if (thread_index >= vec_len (session_main.wrk))
    return 0;

  if (pool_is_free_index (session_main.wrk[thread_index].sessions, si))
    return 0;

  ASSERT (session_is_valid (si, thread_index));
  return pool_elt_at_index (session_main.wrk[thread_index].sessions, si);
}

always_inline session_t *
session_get_from_handle (session_handle_t handle)
{
  session_main_t *smm = &session_main;
  u32 session_index, thread_index;
  session_parse_handle (handle, &session_index, &thread_index);
  return pool_elt_at_index (smm->wrk[thread_index].sessions, session_index);
}

always_inline session_t *
session_get_from_handle_if_valid (session_handle_t handle)
{
  u32 session_index, thread_index;
  session_parse_handle (handle, &session_index, &thread_index);
  return session_get_if_valid (session_index, thread_index);
}

u64 session_segment_handle (session_t * s);

/**
 * Acquires a lock that blocks a session pool from expanding.
 *
 * This is typically used for safely peeking into other threads'
 * pools in order to clone elements. Lock should be dropped as soon
 * as possible by calling @ref session_pool_remove_peeker.
 *
 * NOTE: Avoid using pool_elt_at_index while the lock is held because
 * it may lead to free elt bitmap expansion/contraction!
 */
always_inline void
session_pool_add_peeker (u32 thread_index)
{
  session_worker_t *wrk = &session_main.wrk[thread_index];
  if (thread_index == vlib_get_thread_index ())
    return;
  clib_rwlock_reader_lock (&wrk->peekers_rw_locks);
}

always_inline void
session_pool_remove_peeker (u32 thread_index)
{
  session_worker_t *wrk = &session_main.wrk[thread_index];
  if (thread_index == vlib_get_thread_index ())
    return;
  clib_rwlock_reader_unlock (&wrk->peekers_rw_locks);
}

/**
 * Get session from handle and 'lock' pool resize if not in same thread
 *
 * Caller should drop the peek 'lock' as soon as possible.
 */
always_inline session_t *
session_get_from_handle_safe (u64 handle)
{
  u32 thread_index = session_thread_from_handle (handle);
  session_worker_t *wrk = &session_main.wrk[thread_index];

  if (thread_index == vlib_get_thread_index ())
    {
      return pool_elt_at_index (wrk->sessions,
				session_index_from_handle (handle));
    }
  else
    {
      session_pool_add_peeker (thread_index);
      /* Don't use pool_elt_at index. See @ref session_pool_add_peeker */
      return wrk->sessions + session_index_from_handle (handle);
    }
}

always_inline u32
session_get_index (session_t * s)
{
  return (s - session_main.wrk[s->thread_index].sessions);
}

always_inline session_t *
session_clone_safe (u32 session_index, u32 thread_index)
{
  session_t *old_s, *new_s;
  u32 current_thread_index = vlib_get_thread_index ();

  /* If during the memcpy pool is reallocated AND the memory allocator
   * decides to give the old chunk of memory to somebody in a hurry to
   * scribble something on it, we have a problem. So add this thread as
   * a session pool peeker.
   */
  session_pool_add_peeker (thread_index);
  new_s = session_alloc (current_thread_index);
  old_s = session_main.wrk[thread_index].sessions + session_index;
  clib_memcpy_fast (new_s, old_s, sizeof (*new_s));
  session_pool_remove_peeker (thread_index);
  new_s->thread_index = current_thread_index;
  new_s->session_index = session_get_index (new_s);
  return new_s;
}

int session_open (u32 app_index, session_endpoint_t * tep, u32 opaque);
int session_listen (session_t * s, session_endpoint_cfg_t * sep);
int session_stop_listen (session_t * s);
void session_close (session_t * s);
void session_transport_close (session_t * s);
void session_transport_cleanup (session_t * s);
int session_send_io_evt_to_thread (svm_fifo_t * f,
				   session_evt_type_t evt_type);
int session_enqueue_notify (session_t * s);
int session_dequeue_notify (session_t * s);
int session_send_io_evt_to_thread_custom (void *data, u32 thread_index,
					  session_evt_type_t evt_type);
void session_send_rpc_evt_to_thread (u32 thread_index, void *fp,
				     void *rpc_args);
void session_send_rpc_evt_to_thread_force (u32 thread_index, void *fp,
					   void *rpc_args);
transport_connection_t *session_get_transport (session_t * s);


u8 *format_session (u8 * s, va_list * args);
uword unformat_session (unformat_input_t * input, va_list * args);
uword unformat_transport_connection (unformat_input_t * input,
				     va_list * args);

/*
 * Interface to transport protos
 */

int session_enqueue_stream_connection (transport_connection_t * tc,
				       vlib_buffer_t * b, u32 offset,
				       u8 queue_event, u8 is_in_order);
int session_enqueue_dgram_connection (session_t * s,
				      session_dgram_hdr_t * hdr,
				      vlib_buffer_t * b, u8 proto,
				      u8 queue_event);
int session_stream_connect_notify (transport_connection_t * tc, u8 is_fail);
int session_dgram_connect_notify (transport_connection_t * tc,
				  u32 old_thread_index,
				  session_t ** new_session);
int session_stream_accept_notify (transport_connection_t * tc);
void session_transport_closing_notify (transport_connection_t * tc);
void session_transport_delete_notify (transport_connection_t * tc);
void session_transport_closed_notify (transport_connection_t * tc, hili_tcp_waitclose_timeo_reason_t reason);
void session_transport_reset_notify (transport_connection_t * tc);
int session_stream_accept (transport_connection_t * tc, u32 listener_index,
			   u8 notify);
void session_register_transport (transport_proto_t transport_proto,
				 const transport_proto_vft_t * vft, u8 is_ip4,
				 u32 output_node);
int session_tx_fifo_peek_bytes (transport_connection_t * tc, u8 * buffer,
				u32 offset, u32 max_bytes);
u32 session_tx_fifo_dequeue_drop (transport_connection_t * tc, u32 max_bytes);

u32 transport_max_rx_enqueue (transport_connection_t * tc);
#if 0
always_inline u32
transport_max_rx_enqueue (transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_enqueue (s->rx_fifo);
}
#endif

always_inline u32
transport_max_tx_dequeue (transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_max_dequeue (s->tx_fifo);
}

u32 session_bytes_in_buffer_storage(session_t *s, txrx_buffer_type_t t);

always_inline u32
transport_max_rx_dequeue (transport_connection_t * tc)
{
	session_t *s = session_get (tc->s_index, tc->thread_index);
	if  (is_stream_session_hili_proxy_enable()) {
		return session_bytes_in_buffer_storage(s, RX_BUFFER);
	} else {
		return svm_fifo_max_dequeue (s->rx_fifo);
	}
}

always_inline u32
transport_rx_fifo_size (transport_connection_t * tc)
{
	if  (is_stream_session_hili_proxy_enable()) {
		return default_txrx_buffer_size;
	} else {
  		session_t *s = session_get (tc->s_index, tc->thread_index);
  		return s->rx_fifo->nitems;
	}
}

always_inline u32
transport_tx_fifo_size (transport_connection_t * tc)
{
	if  (is_stream_session_hili_proxy_enable()) {
		return default_txrx_buffer_size;
	} else {
  		session_t *s = session_get (tc->s_index, tc->thread_index);
  		return s->tx_fifo->nitems;
	}
}


always_inline u8
transport_rx_fifo_has_ooo_data (transport_connection_t * tc)
{
  session_t *s = session_get (tc->c_index, tc->thread_index);
  return svm_fifo_has_ooo_data (s->rx_fifo);
}

always_inline f64
transport_dispatch_period (u32 thread_index)
{
  return session_main.wrk[thread_index].dispatch_period;
}

always_inline f64
transport_time_now (u32 thread_index)
{
  return session_main.wrk[thread_index].last_vlib_time;
}

always_inline void
transport_add_tx_event (transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  if (svm_fifo_has_event (s->tx_fifo))
    return;
  session_send_io_evt_to_thread (s->tx_fifo, SESSION_IO_EVT_TX);
}

/*
 * Listen sessions
 */

always_inline u64
listen_session_get_handle (session_t * s)
{
  ASSERT (s->session_state == SESSION_STATE_LISTENING);
  return session_handle (s);
}

always_inline session_t *
listen_session_get_from_handle (session_handle_t handle)
{
  return session_get_from_handle (handle);
}

always_inline void
listen_session_parse_handle (session_handle_t handle, u32 * index,
			     u32 * thread_index)
{
  session_parse_handle (handle, index, thread_index);
}

always_inline session_t *
listen_session_alloc (u8 thread_index, session_type_t type)
{
  session_t *s;
  s = session_alloc (thread_index);
  s->session_type = type;
  hili_session_set_session_state(s, SESSION_STATE_LISTENING);
  return s;
}

always_inline session_t *
listen_session_get (u32 ls_index)
{
  return session_get (ls_index, 0);
}

always_inline void
listen_session_free (session_t * s)
{
  session_free (s);
}

transport_connection_t *listen_session_get_transport (session_t * s);

/*
 * Session layer functions
 */

always_inline session_main_t *
vnet_get_session_main ()
{
  return &session_main;
}

always_inline session_worker_t *
session_main_get_worker (u32 thread_index)
{
  return &session_main.wrk[thread_index];
}

always_inline svm_msg_q_t *
session_main_get_vpp_event_queue (u32 thread_index)
{
  return session_main.wrk[thread_index].vpp_event_queue;
}

always_inline u8
session_main_is_enabled ()
{
  return session_main.is_enabled == 1;
}

#define session_cli_return_if_not_enabled()				\
do {									\
    if (!session_main.is_enabled)				\
      return clib_error_return(0, "session layer is not enabled");	\
} while (0)

int session_main_flush_enqueue_events (u8 proto, u32 thread_index);
int session_main_flush_all_enqueue_events (u8 transport_proto);
void session_flush_frames_main_thread (vlib_main_t * vm);
ssvm_private_t *session_main_get_evt_q_segment (void);
void session_node_enable_disable (u8 is_en);
clib_error_t *vnet_session_enable_disable (vlib_main_t * vm, u8 is_en);

#if 1
/*Start tls proxy*/
/*Used by hili_xx function*/
extern int use_copy_when_recv;
#if 0
extern int agent_proxy_slt_lic;
int tlsproxy_license_setup_and_lookup(void);
int tlsproxy_license_is_valid(void);
#endif

void hili_session_set_session_state(session_t *hili_ss, session_state_t state);
void hili_session_stop_tiemr_queues(session_t *hili_ss, session_worker_t *wrk);
int hili_session_enqueue_stream_connection(transport_connection_t * tc, vlib_buffer_t * b);
int hili_session_enqueue_stream_connection_ooo(session_t *s, vlib_buffer_t * b);
void hili_session_enqueue_stream_try_assemble_packet(session_t *s, vlib_buffer_t *vb);

void stream_session_terminate_transport (session_t * s);

void stream_session_peer_passive_disconnect_notify (transport_connection_t * tc);
void stream_session_window_update_notify(transport_connection_t * tc);

void hili_session_cleanup(session_t *hili_ss);

void hili_add_session_to_tcp_txq(session_worker_t *wrk, session_t *hili_ss);
void hili_add_session_to_tcp_pending_txq(session_worker_t *wrk, session_t *hili_ss);

void hili_session_raise_event(session_t *hili_ss, hili_tq_type_t tq_type);
//int is_stream_session_hili_proxy_enable(void);
int vnet_session_hiliproxy_enable_disable (vlib_main_t * vm, u8 is_en);
u32 stream_session_bytes_in_tbs_storage(transport_connection_t * tc);
int stream_session_peek_bytes_from_tbs_storage (transport_connection_t * tc, u8 * buffer,
                           u32 offset, u32 max_bytes);
u32 stream_session_drop_bytes_from_tbs_storage(transport_connection_t * tc, u32 max_bytes);
u32 hili_transport_max_tx_dequeue (transport_connection_t * tc);
int hili_session_tx_fifo_peek_bytes (transport_connection_t * tc, u8 * buffer, u32 offset, u32 max_bytes);
u32 hili_session_tx_fifo_dequeue_drop (transport_connection_t * tc, u32 max_bytes);
void hili_session_tx_fifo_dequeue_drop_all(session_t *s);

uint32_t     hili_session_has_data(session_t * s);

int     hili_sesssion_under_creating(session_t * s);
int     hili_session_is_reset(session_t * s);
session_cur_status_t     hili_session_current_status(session_t * s);
u8 		hili_session_tx_not_ready(session_t * s);


int     hili_session_send_window(session_t * s);
int     hili_session_pipe_send_window(session_t *pipe);

int32_t hili_session_read(vlib_main_t * vm, session_t * s, vlib_buffer_t **m);
int32_t hili_session_tcp_read(vlib_main_t * vm, session_t * s, vlib_buffer_t **m);
int32_t hili_session_pipe_read(vlib_main_t * vm, session_t * s, vlib_buffer_t **m);

int32_t hili_session_write(vlib_main_t * vm, session_t * s, vlib_buffer_t *m, u_int32_t size);
int32_t hili_session_tcp_write(vlib_main_t * vm, session_t * s, vlib_buffer_t *m, uint32_t size);
int32_t hili_session_pipe_write(vlib_main_t * vm, session_t * s, vlib_buffer_t *m, uint32_t size);


int     hili_session_halfclose(session_t * s);
int     hili_session_tcp_halfclose(session_t * s);
int     hili_session_pipe_halfclose(session_t *pipe);

int     hili_session_close(session_t * s);
int     hili_session_tcp_close(vlib_main_t *vm, session_t * s);
int     hili_session_pipe_close(vlib_main_t *vm, session_t *pipe);

void    hili_session_terminate(session_t * s, uint16_t rst_code);
void    hili_session_tcp_terminate(session_t * s, uint16_t rst_code);
void    hili_session_pipe_terminate(session_t *pipe);

int     hili_session_is_leaving(session_t * s);

session_t * hili_session_pipe_open(int (*rapp)(session_t *), int (*lapp)(session_t *), void *udata, session_t *tcp);

uint32_t hili_session_nread(session_t * s, vlib_buffer_t **mbuf, uint32_t num, u32 alloc_id);

int hili_session_nread_silence(session_t * s, uint32_t off, uint32_t len, void *buf);

vlib_buffer_t *hili_session_vb_split(vlib_main_t *vm, vlib_buffer_t *m0, int len0, u32 alloc_id);

int hili_rte_pktmbuf_cmp(vlib_buffer_t *m1, vlib_buffer_t *m2);

vlib_buffer_t *hili_create_segmented_mbuf(int len, u32 alloc_id);

#define HTTP_BUFFER_ALLOC_ID_BASE	400

#define VLIB_BUFFER_ALLOC_ID_HTTP_400	(HTTP_BUFFER_ALLOC_ID_BASE)
#define VLIB_BUFFER_ALLOC_ID_HTTP_401	(HTTP_BUFFER_ALLOC_ID_BASE + 1)
#define VLIB_BUFFER_ALLOC_ID_HTTP_402	(HTTP_BUFFER_ALLOC_ID_BASE + 2)
#define VLIB_BUFFER_ALLOC_ID_HTTP_403	(HTTP_BUFFER_ALLOC_ID_BASE + 3)

vlib_buffer_t *hili_create_one_mbuf(int len, u32 alloc_id);

vlib_buffer_t *hili_session_str2buffer(char *str, int32_t len);


void hili_session_tcp_chain_recv_vb(vlib_main_t * vm,session_t *hili_ss, vlib_buffer_t *b);
void hili_session_tcp_chain_send_vb(vlib_main_t * vm,session_t *hili_ss, vlib_buffer_t *b);

void session_rte_pktmbuf_dump(vlib_main_t * vm, vlib_buffer_t *m, unsigned dump_len);

vlib_buffer_t * hili_session_get_tbs_buffer(session_t *s, u32 off, u32 len, u32 *off_of_tbs);
u32 hili_session_drop_acked_holding_buffer(session_t *s, u32 len);
//u32 session_bytes_in_buffer_storage(session_t *s, txrx_buffer_type_t t);
always_inline u8
tlsproxy_cons_is_valid (u32 si, u8 thread_index)
{
  tlsproxy_cons_t *s;
  s = pool_elt_at_index (session_main.wrk[thread_index].tlscons, si);
  if (s->thread_index != thread_index || s->tlsproxy_cons_index != si)
    return 0;
  return 1;
}

always_inline tlsproxy_cons_t *
tlsproxy_cons_get (u32 si, u32 thread_index)
{
  ASSERT (tlsproxy_cons_is_valid (si, thread_index));
  return pool_elt_at_index (session_main.wrk[thread_index].tlscons, si);
}

always_inline tlsproxy_cons_t *
tlsproxy_cons_get_if_valid (u64 si, u32 thread_index)
{
  if (thread_index >= vec_len (session_main.wrk))
    return 0;

  if (pool_is_free_index (session_main.wrk[thread_index].tlscons, si))
    return 0;

  ASSERT (tlsproxy_cons_is_valid (si, thread_index));
  return pool_elt_at_index (session_main.wrk[thread_index].tlscons, si);
}


tlsproxy_cons_t *tlsproxy_cons_alloc (u32 thread_index);
void tlsproxy_cons_free (tlsproxy_cons_t * s);

int l4app_proxy_start(session_t *hili_ss);
int tls_server_stack_start(session_t * s);
int dproxy_http_input(session_t *conn);
int hili_session_proxy_forward_handler(session_t *hili_ss);
int hili_session_open_vc_tlsproxy(session_endpoint_t * rmt, u32 opaque);
int hili_handle_active_open_result(session_t *hili_ss, u32 tp_cons_index, u32 tid, u8 is_fail);
/*End tls proxy*/
#endif

#endif /* __included_session_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

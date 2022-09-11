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
/**
 * @file
 * @brief Session and session manager
 */

#include <vnet/session/session.h>
#include <vnet/session/session_debug.h>
#include <vnet/session/application.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>

hili_lb_config_t tlsproxy_main;

session_main_t session_main;

#define _HILI_ENABLE_ 1

#ifdef _HILI_ENABLE_

int debug_session_exchange = 0;
int debug_tcp_reass = 0;

/*If don't use copy, cf test case can't work for some unkonw cause, no time to find it, so just use copy*/
int use_copy_when_recv = 1;

/*return 0 mean the callback handle everything ok, 1 mean meet some error, this no matetr with is_fail*/
always_inline int
hili_session_resign_est_callback(session_t *hili_ss, u32 tp_cons_index, u32 tid, u8 is_fail)
{
	FUNC_TRACE;

	u8 thread_id;

	thread_id = tid;
	if (!is_fail) {
		if (PREDICT_FALSE(tid != hili_ss->thread_index)) {
			LINE_TRACE;
			printf("the tid not eq to thread_id!!!!\n");
			return -1;
		}		
	}
	//return hili_handle_active_open_result(hili_ss, tp_cons_index, tid, is_fail);

	{
	tlsproxy_cons_t *tlsc;

	/*If is_fail is true, then hili_ss should NULL*/
	tlsc = tlsproxy_cons_get(tp_cons_index, tid);
	if (tlsc == NULL) {
		LINE_TRACE;
		printf("failed to get the tlsproxy_cons_t obj!!!!\n");
		return -1;
	}
	return tlsc->act_open_cb_func(hili_ss, tp_cons_index, tid, is_fail);
	}

}


#endif

static inline int
session_send_evt_to_thread (void *data, void *args, u32 thread_index,
			    session_evt_type_t evt_type)
{
  session_event_t *evt;
  svm_msg_q_msg_t msg;
  svm_msg_q_t *mq;
  u32 tries = 0, max_tries;

  mq = session_main_get_vpp_event_queue (thread_index);
  while (svm_msg_q_try_lock (mq))
    {
      max_tries = vlib_get_current_process (vlib_get_main ())? 1e6 : 3;
      if (tries++ == max_tries)
	{
	  SESSION_DBG ("failed to enqueue evt");
	  return -1;
	}
    }
  if (PREDICT_FALSE (svm_msg_q_ring_is_full (mq, SESSION_MQ_IO_EVT_RING)))
    {
      svm_msg_q_unlock (mq);
      return -2;
    }
  msg = svm_msg_q_alloc_msg_w_ring (mq, SESSION_MQ_IO_EVT_RING);
  if (PREDICT_FALSE (svm_msg_q_msg_is_invalid (&msg)))
    {
      svm_msg_q_unlock (mq);
      return -2;
    }
  evt = (session_event_t *) svm_msg_q_msg_data (mq, &msg);
  evt->event_type = evt_type;
  switch (evt_type)
    {
    case SESSION_CTRL_EVT_RPC:
      evt->rpc_args.fp = data;
      evt->rpc_args.arg = args;
      break;
    case SESSION_IO_EVT_TX:
    case SESSION_IO_EVT_TX_FLUSH:
    case SESSION_IO_EVT_BUILTIN_RX:
      evt->session_index = *(u32 *) data;
      break;
    case SESSION_IO_EVT_BUILTIN_TX:
    case SESSION_CTRL_EVT_CLOSE:
      evt->session_handle = session_handle ((session_t *) data);
      break;
    default:
      clib_warning ("evt unhandled!");
      svm_msg_q_unlock (mq);
      return -1;
    }

  svm_msg_q_add_and_unlock (mq, &msg);
  return 0;
}

int
session_send_io_evt_to_thread (svm_fifo_t * f, session_evt_type_t evt_type)
{
  return session_send_evt_to_thread (&f->master_session_index, 0,
				     f->master_thread_index, evt_type);
}

int
session_send_io_evt_to_thread_custom (void *data, u32 thread_index,
				      session_evt_type_t evt_type)
{
  return session_send_evt_to_thread (data, 0, thread_index, evt_type);
}

int
session_send_ctrl_evt_to_thread (session_t * s, session_evt_type_t evt_type)
{
  /* only event supported for now is disconnect */
  ASSERT (evt_type == SESSION_CTRL_EVT_CLOSE);
  return session_send_evt_to_thread (s, 0, s->thread_index,
				     SESSION_CTRL_EVT_CLOSE);
}

void
session_send_rpc_evt_to_thread_force (u32 thread_index, void *fp,
				      void *rpc_args)
{
  session_send_evt_to_thread (fp, rpc_args, thread_index,
			      SESSION_CTRL_EVT_RPC);
}

void
session_send_rpc_evt_to_thread (u32 thread_index, void *fp, void *rpc_args)
{
  if (thread_index != vlib_get_thread_index ())
    session_send_rpc_evt_to_thread_force (thread_index, fp, rpc_args);
  else
    {
      void (*fnp) (void *) = fp;
      fnp (rpc_args);
    }
}

static void
session_program_transport_close (session_t * s)
{
  u32 thread_index = vlib_get_thread_index ();
  session_worker_t *wrk;
  session_event_t *evt;

  /* If we are in the handler thread, or being called with the worker barrier
   * held, just append a new event to pending disconnects vector. */
  if (vlib_thread_is_main_w_barrier () || thread_index == s->thread_index)
    {
      wrk = session_main_get_worker (s->thread_index);
      vec_add2 (wrk->pending_disconnects, evt, 1);
      clib_memset (evt, 0, sizeof (*evt));
      evt->session_handle = session_handle (s);
      evt->event_type = SESSION_CTRL_EVT_CLOSE;
    }
  else
    session_send_ctrl_evt_to_thread (s, SESSION_CTRL_EVT_CLOSE);
}

session_t *
session_alloc (u32 thread_index)
{
  session_worker_t *wrk = &session_main.wrk[thread_index];
  session_t *s;
  u8 will_expand = 0;
  pool_get_aligned_will_expand (wrk->sessions, will_expand,
				CLIB_CACHE_LINE_BYTES);
  /* If we have peekers, let them finish */
  if (PREDICT_FALSE (will_expand && vlib_num_workers ()))
    {
      clib_rwlock_writer_lock (&wrk->peekers_rw_locks);
      pool_get_aligned (wrk->sessions, s, CLIB_CACHE_LINE_BYTES);
      clib_rwlock_writer_unlock (&wrk->peekers_rw_locks);
    }
  else
    {
      pool_get_aligned (wrk->sessions, s, CLIB_CACHE_LINE_BYTES);
    }
  clib_memset (s, 0, sizeof (*s));
  s->session_index = s - wrk->sessions;
  s->thread_index = thread_index;
  return s;
}

void
session_free (session_t * s)
{
  if (CLIB_DEBUG)
    {
      u8 thread_index = s->thread_index;
      clib_memset (s, 0xFA, sizeof (*s));
      pool_put (session_main.wrk[thread_index].sessions, s);
      return;
    }
  SESSION_EVT_DBG (SESSION_EVT_FREE, s);
  pool_put (session_main.wrk[s->thread_index].sessions, s);
}

void
session_free_w_fifos (session_t * s)
{
	segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
	hili_session_cleanup(s);
	session_free (s);
}

/**
 * Cleans up session and lookup table.
 *
 * Transport connection must still be valid.
 */
static void
session_delete (session_t * s)
{
  int rv;

  /* Delete from the main lookup table. */
  if ((rv = session_lookup_del_session (s)))
    clib_warning ("hash delete error, rv %d", rv);

  session_free_w_fifos (s);
}

static session_t *
session_alloc_for_connection (transport_connection_t * tc)
{
  session_t *s;
  u32 thread_index = tc->thread_index;

  ASSERT (thread_index == vlib_get_thread_index ()
	  || transport_protocol_is_cl (tc->proto));

  s = session_alloc (thread_index);
  s->session_type = session_type_from_proto_and_ip (tc->proto, tc->is_ip4);
  s->session_state = SESSION_STATE_CLOSED;

  /* Attach transport to session and vice versa */
  s->connection_index = tc->c_index;
  tc->s_index = s->session_index;
  return s;
}

/**
 * Discards bytes from buffer chain
 *
 * It discards n_bytes_to_drop starting at first buffer after chain_b
 */
always_inline void
session_enqueue_discard_chain_bytes (vlib_main_t * vm, vlib_buffer_t * b,
				     vlib_buffer_t ** chain_b,
				     u32 n_bytes_to_drop)
{
  vlib_buffer_t *next = *chain_b;
  u32 to_drop = n_bytes_to_drop;
  ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
  while (to_drop && (next->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      next = vlib_get_buffer (vm, next->next_buffer);
      if (next->current_length > to_drop)
	{
	  vlib_buffer_advance (next, to_drop);
	  to_drop = 0;
	}
      else
	{
	  to_drop -= next->current_length;
	  next->current_length = 0;
	}
    }
  *chain_b = next;

  if (to_drop == 0)
    b->total_length_not_including_first_buffer -= n_bytes_to_drop;
}

/**
 * Enqueue buffer chain tail
 */
always_inline int
session_enqueue_chain_tail (session_t * s, vlib_buffer_t * b,
			    u32 offset, u8 is_in_order)
{
  vlib_buffer_t *chain_b;
  u32 chain_bi, len, diff;
  vlib_main_t *vm = vlib_get_main ();
  u8 *data;
  u32 written = 0;
  int rv = 0;

  if (is_in_order && offset)
    {
      diff = offset - b->current_length;
      if (diff > b->total_length_not_including_first_buffer)
	return 0;
      chain_b = b;
      session_enqueue_discard_chain_bytes (vm, b, &chain_b, diff);
      chain_bi = vlib_get_buffer_index (vm, chain_b);
    }
  else
    chain_bi = b->next_buffer;

  do
    {
      chain_b = vlib_get_buffer (vm, chain_bi);
      data = vlib_buffer_get_current (chain_b);
      len = chain_b->current_length;
      if (!len)
	continue;
      if (is_in_order)
	{
	  rv = svm_fifo_enqueue_nowait (s->rx_fifo, len, data);
	  if (rv == len)
	    {
	      written += rv;
	    }
	  else if (rv < len)
	    {
	      return (rv > 0) ? (written + rv) : written;
	    }
	  else if (rv > len)
	    {
	      written += rv;

	      /* written more than what was left in chain */
	      if (written > b->total_length_not_including_first_buffer)
		return written;

	      /* drop the bytes that have already been delivered */
	      session_enqueue_discard_chain_bytes (vm, b, &chain_b, rv - len);
	    }
	}
      else
	{
	  rv = svm_fifo_enqueue_with_offset (s->rx_fifo, offset, len, data);
	  if (rv)
	    {
	      clib_warning ("failed to enqueue multi-buffer seg");
	      return -1;
	    }
	  offset += len;
	}
    }
  while ((chain_bi = (chain_b->flags & VLIB_BUFFER_NEXT_PRESENT)
	  ? chain_b->next_buffer : 0));

  if (is_in_order)
    return written;

  return 0;
}

/*
 * Enqueue data for delivery to session peer. Does not notify peer of enqueue
 * event but on request can queue notification events for later delivery by
 * calling stream_server_flush_enqueue_events().
 *
 * @param tc Transport connection which is to be enqueued data
 * @param b Buffer to be enqueued
 * @param offset Offset at which to start enqueueing if out-of-order
 * @param queue_event Flag to indicate if peer is to be notified or if event
 *                    is to be queued. The former is useful when more data is
 *                    enqueued and only one event is to be generated.
 * @param is_in_order Flag to indicate if data is in order
 * @return Number of bytes enqueued or a negative value if enqueueing failed.
 */
int
session_enqueue_stream_connection (transport_connection_t * tc,
				   vlib_buffer_t * b, u32 offset,
				   u8 queue_event, u8 is_in_order)
{
	FUNC_TRACE;
	session_t *s;
	int enqueued = 0, rv, in_order_off;

	s = session_get (tc->s_index, tc->thread_index);

	if (is_in_order) {
		LINE_TRACE;
		if  ((s->app_index == HILI_SESSION_APP_ID) && is_stream_session_hili_proxy_enable()) {
			LINE_TRACE;
			ft_printf("s address %p\n", s);
			if (s->rx_cb_func) {
				LINE_TRACE;
				enqueued = hili_session_enqueue_stream_connection(tc, b);
				ft_printf("s address before call app %p\n", s);
				//s->rx_cb_func(s);
				if (!use_copy_when_recv) {
					b->flags |= VNET_BUFFER_F_SESSION_HOLDING;
				}

				if (1 || enqueued > 0) {
					s->read = 1;
					hili_session_raise_event(s, TQ_TYPE_TCP_TOUCH_APP);
				}
			} else {
				LINE_TRACE;
				enqueued = 0;
			}
			return enqueued;
	  } else {
		enqueued = svm_fifo_enqueue_nowait (s->rx_fifo, b->current_length,vlib_buffer_get_current (b));
		if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && enqueued >= 0)) {
			in_order_off = enqueued > b->current_length ? enqueued : 0;
			rv = session_enqueue_chain_tail (s, b, in_order_off, 1);
			if (rv > 0) {
				enqueued += rv;
			}
		}
	 }
	} else {
		if	((s->app_index == HILI_SESSION_APP_ID) && is_stream_session_hili_proxy_enable()) {
			LINE_TRACE;
			ft_printf("s address %p\n", s);
			if (s->rx_cb_func) {
				LINE_TRACE;
				rv = hili_session_enqueue_stream_connection_ooo(s, b);
				ft_printf("s address before call app %p\n", s);
				if (!use_copy_when_recv) {
				  b->flags |= VNET_BUFFER_F_SESSION_HOLDING;
				}
			} else {
				LINE_TRACE;
				rv = -1;
			}
			return rv;
		}else {
			rv = svm_fifo_enqueue_with_offset(s->rx_fifo, offset, b->current_length, vlib_buffer_get_current(b));
			if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && !rv)) {
				session_enqueue_chain_tail (s, b, offset + b->current_length, 0);
			}
			/* if something was enqueued, report even this as success for ooo
			* segment handling */
			return rv;
		}
    }

  if (queue_event)
    {
      /* Queue RX event on this fifo. Eventually these will need to be flushed
       * by calling stream_server_flush_enqueue_events () */
      session_worker_t *wrk;

      wrk = session_main_get_worker (s->thread_index);
      if (!(s->flags & SESSION_F_RX_EVT))
	{
	  s->flags |= SESSION_F_RX_EVT;
	  vec_add1 (wrk->session_to_enqueue[tc->proto], s->session_index);
	}
    }

  return enqueued;
}

int
session_enqueue_dgram_connection (session_t * s,
				  session_dgram_hdr_t * hdr,
				  vlib_buffer_t * b, u8 proto, u8 queue_event)
{
  int enqueued = 0, rv, in_order_off;

  ASSERT (svm_fifo_max_enqueue (s->rx_fifo)
	  >= b->current_length + sizeof (*hdr));

  svm_fifo_enqueue_nowait (s->rx_fifo, sizeof (session_dgram_hdr_t),
			   (u8 *) hdr);
  enqueued = svm_fifo_enqueue_nowait (s->rx_fifo, b->current_length,
				      vlib_buffer_get_current (b));
  if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && enqueued >= 0))
    {
      in_order_off = enqueued > b->current_length ? enqueued : 0;
      rv = session_enqueue_chain_tail (s, b, in_order_off, 1);
      if (rv > 0)
	enqueued += rv;
    }
  if (queue_event)
    {
      /* Queue RX event on this fifo. Eventually these will need to be flushed
       * by calling stream_server_flush_enqueue_events () */
      session_worker_t *wrk;

      wrk = session_main_get_worker (s->thread_index);
      if (!(s->flags & SESSION_F_RX_EVT))
	{
	  s->flags |= SESSION_F_RX_EVT;
	  vec_add1 (wrk->session_to_enqueue[proto], s->session_index);
	}
    }
  return enqueued;
}

int
session_tx_fifo_peek_bytes (transport_connection_t * tc, u8 * buffer,
			    u32 offset, u32 max_bytes)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_peek (s->tx_fifo, offset, max_bytes, buffer);
}

u32
session_tx_fifo_dequeue_drop (transport_connection_t * tc, u32 max_bytes)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_dequeue_drop (s->tx_fifo, max_bytes);
}

static inline int
session_notify_subscribers (u32 app_index, session_t * s,
			    svm_fifo_t * f, session_evt_type_t evt_type)
{
  app_worker_t *app_wrk;
  application_t *app;
  int i;

  app = application_get (app_index);
  if (!app)
    return -1;

  for (i = 0; i < f->n_subscribers; i++)
    {
      app_wrk = application_get_worker (app, f->subscribers[i]);
      if (!app_wrk)
	continue;
      if (app_worker_lock_and_send_event (app_wrk, s, evt_type))
	return -1;
    }

  return 0;
}

/**
 * Notify session peer that new data has been enqueued.
 *
 * @param s 	Stream session for which the event is to be generated.
 * @param lock 	Flag to indicate if call should lock message queue.
 *
 * @return 0 on success or negative number if failed to send notification.
 */
static inline int
session_enqueue_notify_inline (session_t * s)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    {
      SESSION_DBG ("invalid s->app_index = %d", s->app_wrk_index);
      return 0;
    }

  /* *INDENT-OFF* */
  SESSION_EVT_DBG(SESSION_EVT_ENQ, s, ({
      ed->data[0] = SESSION_IO_EVT_RX;
      ed->data[1] = svm_fifo_max_dequeue (s->rx_fifo);
  }));
  /* *INDENT-ON* */

  s->flags &= ~SESSION_F_RX_EVT;
  if (PREDICT_FALSE (app_worker_lock_and_send_event (app_wrk, s,
						     SESSION_IO_EVT_RX)))
    return -1;

  if (PREDICT_FALSE (svm_fifo_n_subscribers (s->rx_fifo)))
    return session_notify_subscribers (app_wrk->app_index, s,
				       s->rx_fifo, SESSION_IO_EVT_RX);

  return 0;
}

int
session_enqueue_notify (session_t * s)
{
  return session_enqueue_notify_inline (s);
}

int
session_dequeue_notify (session_t * s)
{
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (PREDICT_FALSE (!app_wrk))
    return -1;

  if (PREDICT_FALSE (app_worker_lock_and_send_event (app_wrk, s,
						     SESSION_IO_EVT_TX)))
    return -1;

  if (PREDICT_FALSE (s->tx_fifo->n_subscribers))
    return session_notify_subscribers (app_wrk->app_index, s,
				       s->tx_fifo, SESSION_IO_EVT_TX);

  svm_fifo_clear_tx_ntf (s->tx_fifo);

  return 0;
}

/**
 * Flushes queue of sessions that are to be notified of new data
 * enqueued events.
 *
 * @param thread_index Thread index for which the flush is to be performed.
 * @return 0 on success or a positive number indicating the number of
 *         failures due to API queue being full.
 */
int
session_main_flush_enqueue_events (u8 transport_proto, u32 thread_index)
{
  session_worker_t *wrk = session_main_get_worker (thread_index);
  session_t *s;
  int i, errors = 0;
  u32 *indices;

  indices = wrk->session_to_enqueue[transport_proto];

  for (i = 0; i < vec_len (indices); i++)
    {
      s = session_get_if_valid (indices[i], thread_index);
      if (PREDICT_FALSE (!s))
	{
	  errors++;
	  continue;
	}

      if (PREDICT_FALSE (session_enqueue_notify_inline (s)))
	errors++;
    }

  vec_reset_length (indices);
  wrk->session_to_enqueue[transport_proto] = indices;

  return errors;
}

int
session_main_flush_all_enqueue_events (u8 transport_proto)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  int i, errors = 0;
  for (i = 0; i < 1 + vtm->n_threads; i++)
    errors += session_main_flush_enqueue_events (transport_proto, i);
  return errors;
}

int
session_stream_connect_notify (transport_connection_t * tc, u8 is_fail)
{
  u32 opaque = 0, new_ti, new_si;
  app_worker_t *app_wrk;
  session_t *s = 0;
  u64 ho_handle;

  /*
   * Find connection handle and cleanup half-open table
   */
  ho_handle = session_lookup_half_open_handle (tc);
  if (ho_handle == HALF_OPEN_LOOKUP_INVALID_VALUE)
    {
      SESSION_DBG ("half-open was removed!");
      return -1;
    }
  session_lookup_del_half_open (tc);

  if (is_stream_session_hili_proxy_enable()) {
	  /*Tls proxy case set app as 0xdeadbeef*/
	  if ((ho_handle >> 32) == HILI_OPEN_SESION_APP_ID) {
		  LINE_TRACE;
		  ft_printf("tls proxy client side connection responsed!!!\n");
		  opaque = tc->s_index;
		  if (!is_fail) {
			  s = session_alloc_for_connection (tc);
			  hili_session_set_session_state(s, SESSION_STATE_READY);
			  new_si = s->session_index;
			  new_ti = s->thread_index;
			  s->hili_type = SS_TCP;
			  s->app_index = HILI_SESSION_APP_ID;

		  }
		  /*is_fail stand for the connection, but this if addjudgement stand for callback result*/
		  if (hili_session_resign_est_callback(s, opaque, tc->thread_index,is_fail)) {
			  if (!is_fail) {
	  			return -1;
			  }
		  } else {
		  	/*success*/
			session_lookup_add_connection (tc, session_handle (s));
		  }
		  return 0;
	  }

  }

  /* Get the app's index from the handle we stored when opening connection
   * and the opaque (api_context for external apps) from transport session
   * index */
  app_wrk = app_worker_get_if_valid (ho_handle >> 32);
  if (!app_wrk)
    return -1;

  opaque = tc->s_index;

  if (is_fail)
    return app_worker_connect_notify (app_wrk, s, opaque);

  s = session_alloc_for_connection (tc);
  s->session_state = SESSION_STATE_CONNECTING;
  s->app_wrk_index = app_wrk->wrk_index;
  new_si = s->session_index;
  new_ti = s->thread_index;

  if (app_worker_init_connected (app_wrk, s))
    {
      session_free (s);
      app_worker_connect_notify (app_wrk, 0, opaque);
      return -1;
    }

  if (app_worker_connect_notify (app_wrk, s, opaque))
    {
      s = session_get (new_si, new_ti);
      session_free_w_fifos (s);
      return -1;
    }

  s = session_get (new_si, new_ti);
  s->session_state = SESSION_STATE_READY;
  session_lookup_add_connection (tc, session_handle (s));

  return 0;
}

typedef struct _session_switch_pool_args
{
  u32 session_index;
  u32 thread_index;
  u32 new_thread_index;
  u32 new_session_index;
} session_switch_pool_args_t;

static void
session_switch_pool (void *cb_args)
{
  session_switch_pool_args_t *args = (session_switch_pool_args_t *) cb_args;
  session_t *s;
  ASSERT (args->thread_index == vlib_get_thread_index ());
  s = session_get (args->session_index, args->thread_index);
  s->tx_fifo->master_session_index = args->new_session_index;
  s->tx_fifo->master_thread_index = args->new_thread_index;
  transport_cleanup (session_get_transport_proto (s), s->connection_index,
		     s->thread_index);
  session_free (s);
  clib_mem_free (cb_args);
}

/**
 * Move dgram session to the right thread
 */
int
session_dgram_connect_notify (transport_connection_t * tc,
			      u32 old_thread_index, session_t ** new_session)
{
  session_t *new_s;
  session_switch_pool_args_t *rpc_args;

  /*
   * Clone half-open session to the right thread.
   */
  new_s = session_clone_safe (tc->s_index, old_thread_index);
  new_s->connection_index = tc->c_index;
  new_s->rx_fifo->master_session_index = new_s->session_index;
  new_s->rx_fifo->master_thread_index = new_s->thread_index;
  new_s->session_state = SESSION_STATE_READY;
  session_lookup_add_connection (tc, session_handle (new_s));

  /*
   * Ask thread owning the old session to clean it up and make us the tx
   * fifo owner
   */
  rpc_args = clib_mem_alloc (sizeof (*rpc_args));
  rpc_args->new_session_index = new_s->session_index;
  rpc_args->new_thread_index = new_s->thread_index;
  rpc_args->session_index = tc->s_index;
  rpc_args->thread_index = old_thread_index;
  session_send_rpc_evt_to_thread (rpc_args->thread_index, session_switch_pool,
				  rpc_args);

  tc->s_index = new_s->session_index;
  new_s->connection_index = tc->c_index;
  *new_session = new_s;
  return 0;
}

/**
 * Notification from transport that connection is being closed.
 *
 * A disconnect is sent to application but state is not removed. Once
 * disconnect is acknowledged by application, session disconnect is called.
 * Ultimately this leads to close being called on transport (passive close).
 */
void
session_transport_closing_notify (transport_connection_t * tc)
{
	app_worker_t *app_wrk;
	session_t *s;

	s = session_get (tc->s_index, tc->thread_index);
	if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
		return;

	hili_session_set_session_state(s, SESSION_STATE_TRANSPORT_CLOSING);
	if  (is_stream_session_hili_proxy_enable()) {
		if  (s && s->rx_cb_func) {
			s->hili_flags |= SS_TCP_RECV_FISRT_FIN;
			//s->rx_cb_func(s);
			s->read = 1;
			hili_session_raise_event(s, TQ_TYPE_TCP_TOUCH_APP);
		}
	} else {
		app_wrk = app_worker_get (s->app_wrk_index);
		app_worker_close_notify (app_wrk, s);
	}
}

/**
 * Notification from transport that connection is being deleted
 *
 * This removes the session if it is still valid. It should be called only on
 * previously fully established sessions. For instance failed connects should
 * call stream_session_connect_notify and indicate that the connect has
 * failed.
 */
void
session_transport_delete_notify (transport_connection_t * tc)
{
  session_t *s;

  /* App might've been removed already */
  if (!(s = session_get_if_valid (tc->s_index, tc->thread_index)))
    return;

  hili_session_tx_fifo_dequeue_drop_all(s);

  switch (s->session_state)
    {
    case SESSION_STATE_CREATED:
      /* Session was created but accept notification was not yet sent to the
       * app. Cleanup everything. */
      session_lookup_del_session (s);
      session_free_w_fifos (s);
      break;
    case SESSION_STATE_ACCEPTING:
    case SESSION_STATE_TRANSPORT_CLOSING:
      /* If transport finishes or times out before we get a reply
       * from the app, mark transport as closed and wait for reply
       * before removing the session. Cleanup session table in advance
       * because transport will soon be closed and closed sessions
       * are assumed to have been removed from the lookup table */
      session_lookup_del_session (s);
	  hili_session_set_session_state(s, SESSION_STATE_TRANSPORT_CLOSED);
      break;
    case SESSION_STATE_CLOSING:
    case SESSION_STATE_CLOSED_WAITING:
      /* Cleanup lookup table as transport needs to still be valid.
       * Program transport close to ensure that all session events
       * have been cleaned up. Once transport close is called, the
       * session is just removed because both transport and app have
       * confirmed the close*/
      session_lookup_del_session (s);
	  hili_session_set_session_state(s, SESSION_STATE_TRANSPORT_CLOSED);
      session_program_transport_close (s);
      break;
    case SESSION_STATE_TRANSPORT_CLOSED:
      break;
    case SESSION_STATE_CLOSED:
      session_delete (s);
      break;
    default:
      clib_warning ("session state %u", s->session_state);
      session_delete (s);
      break;
    }
}

/**
 * Notification from transport that session can be closed
 *
 * Should be called by transport only if it was closed with non-empty
 * tx fifo and once it decides to begin the closing procedure prior to
 * issuing a delete notify. This gives the chance to the session layer
 * to cleanup any outstanding events.
 */
void
session_transport_closed_notify(transport_connection_t * tc, hili_tcp_waitclose_timeo_reason_t reason)
{
	session_t *s;
	u64 old_hili_flags;
	int notify_app = 0;

	if (!(s = session_get_if_valid (tc->s_index, tc->thread_index))) {
		return;
	}

	old_hili_flags = s->hili_flags;
	switch(reason)
	{
		case WAITCLOSE_TIMEO_REASON_CLOSE_WAIT_TOO_LONG:
			s->hili_flags |= (SS_TCP_CLOSE_WAIT_TOO_LONG | SS_TCP_RESET);
			notify_app = 1;
			break;
		case WAITCLOSE_TIMEO_REASON_FIN_WAIT_1_TOO_LONG:
			s->hili_flags |= (SS_TCP_F1_TOO_LONG | SS_TCP_RESET);
			notify_app = 1;
			break;
		case WAITCLOSE_TIMEO_REASON_FIN_WAIT_1_NO_RESPONSE:
			s->hili_flags |= (SS_TCP_F1_NO_RESP_TOO_LONG | SS_TCP_RESET);
			notify_app = 1;
			break;
		case WAITCLOSE_TIMEO_REASON_LAST_ACK_AND_CLOSING:
		case WAITCLOSE_TIMEO_REASON_NON_EST_RESET_COMING:
			break;
		default:
			clib_warning("Unkonw reason");
			break;
	}

	/* If app close has not been received or has not yet resulted in
	* a transport close, only mark the session transport as closed */
	if (notify_app) {
		//session_lookup_del_session (s);
		if (s->rx_cb_func && !(old_hili_flags & SS_TCP_RESET) && !(old_hili_flags & SS_TCP_APPTERM)) {
			hili_session_set_session_state(s, SESSION_STATE_CLOSED);
			s->read = 1;
			s->rx_cb_func(s);
			//hili_session_raise_event(s, TQ_TYPE_TCP_TOUCH_APP);
		}
	} else if (s->session_state <= SESSION_STATE_CLOSING) {
		session_lookup_del_session (s);
		hili_session_set_session_state(s, SESSION_STATE_TRANSPORT_CLOSED);
	} else {
		hili_session_set_session_state(s, SESSION_STATE_CLOSED);
	}
}

/**
 * Notify application that connection has been reset.
 */
void
session_transport_reset_notify (transport_connection_t * tc)
{
	app_worker_t *app_wrk;
	session_t *s;

	s = session_get (tc->s_index, tc->thread_index);

	if (is_stream_session_hili_proxy_enable()) {
		if (s->rx_cb_func && !(s->hili_flags & SS_TCP_RESET)) {
			s->hili_flags |= SS_TCP_RESET;
			hili_session_set_session_state(s, SESSION_STATE_CLOSED);
			//s->rx_cb_func(s);
			s->read = 1;
			hili_session_raise_event(s, TQ_TYPE_TCP_TOUCH_APP);
		} else if (s->hili_flags & SS_TCP_APPTERM) {
			hili_session_set_session_state(s, SESSION_STATE_CLOSED);
		}
	}

	if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
		return;
	hili_session_set_session_state(s, SESSION_STATE_TRANSPORT_CLOSING);

	hili_session_tx_fifo_dequeue_drop_all(s);

	if (!is_stream_session_hili_proxy_enable()) {
		app_wrk = app_worker_get (s->app_wrk_index);
		app_worker_reset_notify (app_wrk, s);
	}
}


int
session_stream_accept_notify (transport_connection_t * tc)
{
	FUNC_TRACE;
	app_worker_t *app_wrk;
	session_t *s, *listener;

	s = session_get (tc->s_index, tc->thread_index);
	ft_printf("s address %p, s value : %p\n", &s, s);

	if  (is_stream_session_hili_proxy_enable()) {
		if (s->rx_cb_func) {
			listener = listen_session_get(s->listener_index);
			s->opaque = listener->opaque;
			s->flags |= SS_TCP_AS_SERVER;
			s->app_index = HILI_SESSION_APP_ID;
			//s->rx_cb_func(s);
			hili_session_raise_event(s, TQ_TYPE_TCP_TOUCH_APP);
			ft_printf("s address %p, s value : %p, s->cons_side address : %p\n", &s, s, s->cons_side);
			return 0;
		} else {
			clib_warning("accept notify but no rx_cb_func, return -1!");
			return -1;
		}
	} else {

		app_wrk = app_worker_get_if_valid (s->app_wrk_index);
		if (!app_wrk)
		return -1;
		s->session_state = SESSION_STATE_ACCEPTING;
		return app_worker_accept_notify (app_wrk, s);
	}
}

/**
 * Accept a stream session. Optionally ping the server by callback.
 */
int
session_stream_accept (transport_connection_t * tc, u32 listener_index,
		       u8 notify)
{
  session_t *s;
  int rv;

  s = session_alloc_for_connection (tc);
  s->listener_index = listener_index;
  hili_session_set_session_state(s, SESSION_STATE_CREATED);
  session_t *listener;

  listener = listen_session_get (s->listener_index);

  if (is_stream_session_hili_proxy_enable()) {
		if (1) {
			s->flags |= SS_TCP_AS_SERVER;
			s->rx_cb_func = listener->rx_cb_func;
		} else {
			session_log_notice("condition is invalid, so drop the SYN packet!");
			return -1;
		}
  } else {
		if ((rv = app_worker_init_accepted (s)))
			return rv;
  	}
  session_lookup_add_connection (tc, session_handle (s));

  /* Shoulder-tap the server */
  if (notify && !is_stream_session_hili_proxy_enable())
    {
      app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
      return app_worker_accept_notify (app_wrk, s);
    }

  return 0;
}

int
session_open_cl (u32 app_wrk_index, session_endpoint_t * rmt, u32 opaque)
{
  transport_connection_t *tc;
  transport_endpoint_cfg_t *tep;
  app_worker_t *app_wrk;
  session_handle_t sh;
  session_t *s;
  int rv;

  tep = session_endpoint_to_transport_cfg (rmt);
  rv = transport_connect (rmt->transport_proto, tep);
  if (rv < 0)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return VNET_API_ERROR_SESSION_CONNECT;
    }

  tc = transport_get_half_open (rmt->transport_proto, (u32) rv);

  /* For dgram type of service, allocate session and fifos now */
  app_wrk = app_worker_get (app_wrk_index);
  s = session_alloc_for_connection (tc);
  s->app_wrk_index = app_wrk->wrk_index;
  s->session_state = SESSION_STATE_OPENED;
  if (app_worker_init_connected (app_wrk, s))
    {
      session_free (s);
      return -1;
    }

  sh = session_handle (s);
  session_lookup_add_connection (tc, sh);

  return app_worker_connect_notify (app_wrk, s, opaque);
}

int
session_open_vc (u32 app_wrk_index, session_endpoint_t * rmt, u32 opaque)
{
  transport_connection_t *tc;
  transport_endpoint_cfg_t *tep;
  u64 handle;
  int rv;

  tep = session_endpoint_to_transport_cfg (rmt);
  rv = transport_connect (rmt->transport_proto, tep);
  if (rv < 0)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return VNET_API_ERROR_SESSION_CONNECT;
    }

  tc = transport_get_half_open (rmt->transport_proto, (u32) rv);

  /* If transport offers a stream service, only allocate session once the
   * connection has been established.
   * Add connection to half-open table and save app and tc index. The
   * latter is needed to help establish the connection while the former
   * is needed when the connect notify comes and we have to notify the
   * external app
   */
  handle = (((u64) app_wrk_index) << 32) | (u64) tc->c_index;
  session_lookup_add_half_open (tc, handle);

  /* Store api_context (opaque) for when the reply comes. Not the nicest
   * thing but better than allocating a separate half-open pool.
   */
  tc->s_index = opaque;
  return 0;
}

int
session_open_app (u32 app_wrk_index, session_endpoint_t * rmt, u32 opaque)
{
  session_endpoint_cfg_t *sep = (session_endpoint_cfg_t *) rmt;
  transport_endpoint_cfg_t *tep_cfg = session_endpoint_to_transport_cfg (sep);

  sep->app_wrk_index = app_wrk_index;
  sep->opaque = opaque;

  return transport_connect (rmt->transport_proto, tep_cfg);
}

typedef int (*session_open_service_fn) (u32, session_endpoint_t *, u32);

/* *INDENT-OFF* */
static session_open_service_fn session_open_srv_fns[TRANSPORT_N_SERVICES] = {
  session_open_vc,
  session_open_cl,
  session_open_app,
};
/* *INDENT-ON* */

/**
 * Ask transport to open connection to remote transport endpoint.
 *
 * Stores handle for matching request with reply since the call can be
 * asynchronous. For instance, for TCP the 3-way handshake must complete
 * before reply comes. Session is only created once connection is established.
 *
 * @param app_index Index of the application requesting the connect
 * @param st Session type requested.
 * @param tep Remote transport endpoint
 * @param opaque Opaque data (typically, api_context) the application expects
 * 		 on open completion.
 */
int
session_open (u32 app_wrk_index, session_endpoint_t * rmt, u32 opaque)
{
  transport_service_type_t tst;
  tst = transport_protocol_service_type (rmt->transport_proto);
  return session_open_srv_fns[tst] (app_wrk_index, rmt, opaque);
}

/**
 * Ask transport to listen on session endpoint.
 *
 * @param s Session for which listen will be called. Note that unlike
 * 	    established sessions, listen sessions are not associated to a
 * 	    thread.
 * @param sep Local endpoint to be listened on.
 */
int
session_listen (session_t * ls, session_endpoint_cfg_t * sep)
{
  transport_endpoint_t *tep;
  u32 tc_index, s_index;

  /* Transport bind/listen */
  tep = session_endpoint_to_transport (sep);
  s_index = ls->session_index;
  tc_index = transport_start_listen (session_get_transport_proto (ls),
				     s_index, tep);

  if (tc_index == (u32) ~ 0)
    return -1;

  /* Attach transport to session. Lookup tables are populated by the app
   * worker because local tables (for ct sessions) are not backed by a fib */
  ls = listen_session_get (s_index);
  ls->connection_index = tc_index;

  return 0;
}

/**
 * Ask transport to stop listening on local transport endpoint.
 *
 * @param s Session to stop listening on. It must be in state LISTENING.
 */
int
session_stop_listen (session_t * s)
{
  transport_proto_t tp = session_get_transport_proto (s);
  transport_connection_t *tc;

  if (s->session_state != SESSION_STATE_LISTENING)
    return -1;

  tc = transport_get_listener (tp, s->connection_index);
  if (!tc)
    return VNET_API_ERROR_ADDRESS_NOT_IN_USE;

  session_lookup_del_connection (tc);
  transport_stop_listen (tp, s->connection_index);
  return 0;
}

/**
 * Initialize session closing procedure.
 *
 * Request is always sent to session node to ensure that all outstanding
 * requests are served before transport is notified.
 */
void
session_close (session_t * s)
{
	if (!s)
		return;

	if (s->session_state >= SESSION_STATE_CLOSING) {
		/* Session will only be removed once both app and transport
		* acknowledge the close */
		if (s->session_state == SESSION_STATE_TRANSPORT_CLOSED) {
			session_program_transport_close (s);
		}
		/* Session already closed. Clear the tx fifo */
		if (s->session_state == SESSION_STATE_CLOSED) {
			hili_session_tx_fifo_dequeue_drop_all(s);
		}
		return;
	}

	hili_session_set_session_state(s, SESSION_STATE_CLOSING);
	session_program_transport_close (s);
}

/**
 * Notify transport the session can be disconnected. This should eventually
 * result in a delete notification that allows us to cleanup session state.
 * Called for both active/passive disconnects.
 *
 * Must be called from the session's thread.
 * this function is the final result of session_close and handle in session node.
 */
void
session_transport_close (session_t * s)
{
	/* If transport is already closed, just free the session */
	/*SESSION_STATE_CLOSED_WAITING will trigger this in delete notify*/
	if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSED) {
		hili_session_set_session_state(s, SESSION_STATE_CLOSED);
		return;
	}

	/* If tx queue wasn't drained, change state to closed waiting for transport.
	* This way, the transport, if it so wishes, can continue to try sending the
	* outstanding data (in closed state it cannot). It MUST however at one
	* point, either after sending everything or after a timeout, call delete
	* notify. This will finally lead to the complete cleanup of the session.
	*/
	if (session_bytes_in_buffer_storage(s, TX_BUFFER)) {
		/*Some time later delete notify check this state and 
		 *set to SESSION_STATE_TRANSPORT_CLOSED, which will hit above code 
		 * when this function enter for second time.
		 */
		hili_session_set_session_state(s, SESSION_STATE_CLOSED_WAITING);
	} else {
		/*when set SESSION_STATE_CLOSED, delete notify can call session_delete*/
		hili_session_set_session_state(s, SESSION_STATE_CLOSED);
	}
	transport_close (session_get_transport_proto (s), s->connection_index, s->thread_index);
}

/**
 * Cleanup transport and session state.
 *
 * Notify transport of the cleanup and free the session. This should
 * be called only if transport reported some error and is already
 * closed.
 * Useless, only be caled by session_test_endpoint_cfg
 */
void
session_transport_cleanup (session_t * s)
{
  hili_session_set_session_state(s, SESSION_STATE_CLOSED);
  /* Delete from main lookup table before we axe the the transport */
  session_lookup_del_session (s);
  transport_cleanup (session_get_transport_proto (s), s->connection_index,
		     s->thread_index);
  /* Since we called cleanup, no delete notification will come. So, make
   * sure the session is properly freed. */
  session_free_w_fifos (s);
}

/**
 * Allocate event queues in the shared-memory segment
 *
 * That can either be a newly created memfd segment, that will need to be
 * mapped by all stack users, or the binary api's svm region. The latter is
 * assumed to be already mapped. NOTE that this assumption DOES NOT hold if
 * api clients bootstrap shm api over sockets (i.e. use memfd segments) and
 * vpp uses api svm region for event queues.
 */
void
session_vpp_event_queues_allocate (session_main_t * smm)
{
  u32 evt_q_length = 2048, evt_size = sizeof (session_event_t);
  ssvm_private_t *eqs = &smm->evt_qs_segment;
  api_main_t *am = &api_main;
  uword eqs_size = 64 << 20;
  pid_t vpp_pid = getpid ();
  void *oldheap;
  int i;

  if (smm->configured_event_queue_length)
    evt_q_length = smm->configured_event_queue_length;

  if (smm->evt_qs_use_memfd_seg)
    {
      if (smm->evt_qs_segment_size)
	eqs_size = smm->evt_qs_segment_size;

      eqs->ssvm_size = eqs_size;
      eqs->i_am_master = 1;
      eqs->my_pid = vpp_pid;
      eqs->name = format (0, "%s%c", "evt-qs-segment", 0);
      eqs->requested_va = smm->session_baseva;

      if (ssvm_master_init (eqs, SSVM_SEGMENT_MEMFD))
	{
	  clib_warning ("failed to initialize queue segment");
	  return;
	}
    }

  if (smm->evt_qs_use_memfd_seg)
    oldheap = ssvm_push_heap (eqs->sh);
  else
    oldheap = svm_push_data_heap (am->vlib_rp);

  for (i = 0; i < vec_len (smm->wrk); i++)
    {
      svm_msg_q_cfg_t _cfg, *cfg = &_cfg;
      svm_msg_q_ring_cfg_t rc[SESSION_MQ_N_RINGS] = {
	{evt_q_length, evt_size, 0}
	,
	{evt_q_length >> 1, 256, 0}
      };
      cfg->consumer_pid = 0;
      cfg->n_rings = 2;
      cfg->q_nitems = evt_q_length;
      cfg->ring_cfgs = rc;
      smm->wrk[i].vpp_event_queue = svm_msg_q_alloc (cfg);
      if (smm->evt_qs_use_memfd_seg)
	{
	  if (svm_msg_q_alloc_consumer_eventfd (smm->wrk[i].vpp_event_queue))
	    clib_warning ("eventfd returned");
	}
    }

  if (smm->evt_qs_use_memfd_seg)
    ssvm_pop_heap (oldheap);
  else
    svm_pop_heap (oldheap);
}

ssvm_private_t *
session_main_get_evt_q_segment (void)
{
  session_main_t *smm = &session_main;
  if (smm->evt_qs_use_memfd_seg)
    return &smm->evt_qs_segment;
  return 0;
}

u64
session_segment_handle (session_t * s)
{
  svm_fifo_t *f;

  if (s->session_state == SESSION_STATE_LISTENING)
    return SESSION_INVALID_HANDLE;

  f = s->rx_fifo;
  return segment_manager_make_segment_handle (f->segment_manager,
					      f->segment_index);
}

/* *INDENT-OFF* */
static session_fifo_rx_fn *session_tx_fns[TRANSPORT_TX_N_FNS] = {
    session_tx_fifo_peek_and_snd,
    session_tx_fifo_dequeue_and_snd,
    session_tx_fifo_dequeue_internal,
    session_tx_fifo_dequeue_and_snd
};
/* *INDENT-ON* */

/**
 * Initialize session layer for given transport proto and ip version
 *
 * Allocates per session type (transport proto + ip version) data structures
 * and adds arc from session queue node to session type output node.
 */
void
session_register_transport (transport_proto_t transport_proto,
			    const transport_proto_vft_t * vft, u8 is_ip4,
			    u32 output_node)
{
  session_main_t *smm = &session_main;
  session_type_t session_type;
  u32 next_index = ~0;

  session_type = session_type_from_proto_and_ip (transport_proto, is_ip4);

  vec_validate (smm->session_type_to_next, session_type);
  vec_validate (smm->session_tx_fns, session_type);

  /* *INDENT-OFF* */
  if (output_node != ~0)
    {
      foreach_vlib_main (({
          next_index = vlib_node_add_next (this_vlib_main,
                                           session_queue_node.index,
                                           output_node);
      }));
    }
  /* *INDENT-ON* */

  smm->session_type_to_next[session_type] = next_index;
  smm->session_tx_fns[session_type] = session_tx_fns[vft->tx_type];
}

transport_connection_t *
session_get_transport (session_t * s)
{
  if (s->session_state != SESSION_STATE_LISTENING)
    return transport_get_connection (session_get_transport_proto (s),
				     s->connection_index, s->thread_index);
  else
    return transport_get_listener (session_get_transport_proto (s),
				   s->connection_index);
}

transport_connection_t *
listen_session_get_transport (session_t * s)
{
  return transport_get_listener (session_get_transport_proto (s),
				 s->connection_index);
}

void
session_flush_frames_main_thread (vlib_main_t * vm)
{
  ASSERT (vlib_get_thread_index () == 0);
  vlib_process_signal_event_mt (vm, session_queue_process_node.index,
				SESSION_Q_PROCESS_FLUSH_FRAMES, 0);
}

static clib_error_t *
session_manager_main_enable (vlib_main_t * vm)
{
  segment_manager_main_init_args_t _sm_args = { 0 }, *sm_args = &_sm_args;
  session_main_t *smm = &session_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads, preallocated_sessions_per_worker;
  session_worker_t *wrk;
  int i;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  if (num_threads < 1)
    return clib_error_return (0, "n_thread_stacks not set");

  /* Allocate cache line aligned worker contexts */
  vec_validate_aligned (smm->wrk, num_threads - 1, CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < num_threads; i++)
    {
      wrk = &smm->wrk[i];
      vec_validate (wrk->free_event_vector, 128);
      _vec_len (wrk->free_event_vector) = 0;
      vec_validate (wrk->pending_event_vector, 128);
      _vec_len (wrk->pending_event_vector) = 0;
      vec_validate (wrk->pending_disconnects, 128);
      _vec_len (wrk->pending_disconnects) = 0;
      vec_validate (wrk->postponed_event_vector, 128);
      _vec_len (wrk->postponed_event_vector) = 0;

      wrk->last_vlib_time = vlib_time_now (vlib_mains[i]);
      wrk->dispatch_period = 500e-6;

      if (num_threads > 1) {
		clib_rwlock_init (&smm->wrk[i].peekers_rw_locks); 
		clib_rwlock_init (&smm->wrk[i].tlscons_peekers_rw_locks);
      }
	  TAILQ_INIT(&wrk->session_ue_queue);
	  TAILQ_INIT(&wrk->session_txe_queue);
	  TAILQ_INIT(&wrk->session_ptxe_queue);
	  TAILQ_INIT(&wrk->session_hclosee_queue);
	  TAILQ_INIT(&wrk->session_terme_queue);

	  TAILQ_INIT(&wrk->session_pipe_ue_queue);
	  TAILQ_INIT(&wrk->session_pipe_de_queue);

    }

#if SESSION_DEBUG
  vec_validate (smm->last_event_poll_by_thread, num_threads - 1);
#endif

  /* Allocate vpp event queues segment and queue */
  session_vpp_event_queues_allocate (smm);

  /* Initialize fifo segment main baseva and timeout */
  sm_args->baseva = smm->session_baseva + smm->evt_qs_segment_size;
  sm_args->size = smm->session_va_space_size;
  segment_manager_main_init (sm_args);
 
  if (smm->preallocated_sessions == 0) {
	smm->preallocated_sessions = 512;
	ft_printf("preallocated_sessions is 0, so set to value 512\n");
  } else {
	ft_printf("The smm->preallocated_sessions config value : %u\n", smm->preallocated_sessions);
  }

  /* Preallocate sessions */
  if (smm->preallocated_sessions)
    {
      if (num_threads == 1)
	{
	  pool_init_fixed (smm->wrk[0].sessions, smm->preallocated_sessions);
	  pool_init_fixed (smm->wrk[0].tlscons,  smm->preallocated_sessions);
	}
      else
	{
	  int j;
	  preallocated_sessions_per_worker =
	    (1.1 * (f64) smm->preallocated_sessions /
	     (f64) (num_threads - 1));

	  for (j = 1; j < num_threads; j++)
	    {
	      pool_init_fixed (smm->wrk[j].sessions, preallocated_sessions_per_worker);
		  pool_init_fixed (smm->wrk[j].tlscons, preallocated_sessions_per_worker);
	    }
	}
    }

  session_lookup_init ();
  app_namespaces_init ();
  transport_init ();

  smm->is_enabled = 1;

  /* Enable transports */
  transport_enable_disable (vm, 1);
  transport_init_tx_pacers_period ();
  return 0;
}

void
session_node_enable_disable (u8 is_en)
{
  u8 state = is_en ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u8 have_workers = vtm->n_threads != 0;

  /* *INDENT-OFF* */
  foreach_vlib_main (({
    if (have_workers && ii == 0)
      {
	vlib_node_set_state (this_vlib_main, session_queue_process_node.index,
	                     state);
	if (is_en)
	  {
	    vlib_node_t *n = vlib_get_node (this_vlib_main,
	                                    session_queue_process_node.index);
	    vlib_start_process (this_vlib_main, n->runtime_index);
	  }
	else
	  {
	    vlib_process_signal_event_mt (this_vlib_main,
	                                  session_queue_process_node.index,
	                                  SESSION_Q_PROCESS_STOP, 0);
	  }

	continue;
      }
    vlib_node_set_state (this_vlib_main, session_queue_node.index,
                         state);
  }));
  /* *INDENT-ON* */
}

clib_error_t *
vnet_session_enable_disable (vlib_main_t * vm, u8 is_en)
{
  clib_error_t *error = 0;
  if (is_en)
    {
      if (session_main.is_enabled)
	return 0;

      session_node_enable_disable (is_en);
      error = session_manager_main_enable (vm);
    }
  else
    {
      session_main.is_enabled = 0;
      session_node_enable_disable (is_en);
    }

  return error;
}

clib_error_t *
session_manager_main_init (vlib_main_t * vm)
{
  session_main_t *smm = &session_main;
  smm->session_baseva = HIGH_SEGMENT_BASEVA;
#if (HIGH_SEGMENT_BASEVA > (4ULL << 30))
  smm->session_va_space_size = 128ULL << 30;
  smm->evt_qs_segment_size = 64 << 20;
#else
  smm->session_va_space_size = 128 << 20;
  smm->evt_qs_segment_size = 1 << 20;
#endif
  smm->is_enabled = 0;
  smm->log_class = vlib_log_register_class ("session", 0);
  return 0;
}

VLIB_INIT_FUNCTION (session_manager_main_init);

static clib_error_t *
session_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  session_main_t *smm = &session_main;
  u32 nitems;
  uword tmp;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "event-queue-length %d", &nitems))
	{
	  if (nitems >= 2048)
	    smm->configured_event_queue_length = nitems;
	  else
	    clib_warning ("event queue length %d too small, ignored", nitems);
	}
      else if (unformat (input, "preallocated-sessions %d",
			 &smm->preallocated_sessions))
	;
      else if (unformat (input, "v4-session-table-buckets %d",
			 &smm->configured_v4_session_table_buckets))
	;
      else if (unformat (input, "v4-halfopen-table-buckets %d",
			 &smm->configured_v4_halfopen_table_buckets))
	;
      else if (unformat (input, "v6-session-table-buckets %d",
			 &smm->configured_v6_session_table_buckets))
	;
      else if (unformat (input, "v6-halfopen-table-buckets %d",
			 &smm->configured_v6_halfopen_table_buckets))
	;
      else if (unformat (input, "v4-session-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v4_session_table_memory = tmp;
	}
      else if (unformat (input, "v4-halfopen-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v4_halfopen_table_memory = tmp;
	}
      else if (unformat (input, "v6-session-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v6_session_table_memory = tmp;
	}
      else if (unformat (input, "v6-halfopen-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v6_halfopen_table_memory = tmp;
	}
      else if (unformat (input, "local-endpoints-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->local_endpoints_table_memory = tmp;
	}
      else if (unformat (input, "local-endpoints-table-buckets %d",
			 &smm->local_endpoints_table_buckets))
	;
      else if (unformat (input, "evt_qs_memfd_seg"))
	smm->evt_qs_use_memfd_seg = 1;
      else if (unformat (input, "evt_qs_seg_size %U", unformat_memory_size,
			 &smm->evt_qs_segment_size))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (session_config_fn, "session");


#if 1
/********LB config start****************/
hili_lb_config_main_t hili_lb_config_main;

hili_lb_config_t *
hili_lb_config_alloc(u32 thread_index)
{
	FUNC_TRACE;
	hili_lb_config_main_t *hlcm = &hili_lb_config_main;
	hili_lb_config_t *s;
	u8 will_expand = 0;

	pool_get_aligned_will_expand (hlcm->hili_lb_config_pools[thread_index], will_expand, CLIB_CACHE_LINE_BYTES);
	/* If we have peekers, let them finish */
	if (PREDICT_FALSE (will_expand && vlib_num_workers ())) {
		clib_rwlock_writer_lock (&hlcm->hili_lb_config_peekers_rw_locks[thread_index]);
		pool_get_aligned (hili_lb_config_main.hili_lb_config_pools[thread_index], s, CLIB_CACHE_LINE_BYTES);
		clib_rwlock_writer_unlock (&hlcm->hili_lb_config_peekers_rw_locks[thread_index]);
	} else {
		pool_get_aligned (hili_lb_config_main.hili_lb_config_pools[thread_index], s, CLIB_CACHE_LINE_BYTES);
	}
	memset (s, 0, sizeof (*s));
	s->hili_lb_config_index = s - hili_lb_config_main.hili_lb_config_pools[thread_index];
	s->thread_index = thread_index;
	return s;
}

void
hili_lb_config_free(hili_lb_config_t * s)
{
	pool_put (hili_lb_config_main.hili_lb_config_pools[s->thread_index], s);
	if (CLIB_DEBUG) {
		memset (s, 0xFA, sizeof (*s));
	}
}

hili_lb_config_t *
hili_get_lb_config_by_name(char *lb_name_arg)
{
	FUNC_TRACE;
	hili_lb_config_main_t *hlcm = &hili_lb_config_main;
	hili_lb_config_t *lbcp;
	hili_lb_config_t *pool;
	int i;

	for (i = 0; i < vec_len(hlcm->hili_lb_config_pools); i++) {
		pool = hlcm->hili_lb_config_pools[i];
		if (!pool_elts(pool)) {
			return NULL;
		} else {
			pool_foreach (lbcp, pool, ({if(strcmp(lbcp->lb_name, lb_name_arg) == 0) {return lbcp;}}));
		}
	}
	return NULL;
}


static clib_error_t *
hili_lb_config_main_enable(vlib_main_t *vm)
{
	hili_lb_config_main_t *hlcm = &hili_lb_config_main;

	vlib_thread_main_t *vtm = vlib_get_thread_main ();
	u32 num_threads, preallocated_data_per_worker;
	int i, j;

	num_threads = 1 /* main thread */  + vtm->n_threads;

	if (num_threads < 1) {
		return clib_error_return (0, "n_thread_stacks not set");
	}

	hlcm->is_enabled = 1;
	/* configure per-thread ** vectors */
	vec_validate (hlcm->hili_lb_config_pools, num_threads - 1);
	vec_validate (hlcm->hili_lb_config_peekers_rw_locks, num_threads - 1);

	if (num_threads > 1) {
		for (i = 0; i < num_threads; i++) {
			clib_rwlock_init(&hlcm->hili_lb_config_peekers_rw_locks[i]);
		}
	}

	if (hlcm->preallocated_lb_config) {
		ft_printf("hlcm->preallocated_lb_config config value : %u\n", hlcm->preallocated_lb_config);
		if (num_threads == 1) {
			pool_init_fixed (hlcm->hili_lb_config_pools[0], hlcm->preallocated_lb_config);
		} else {
			preallocated_data_per_worker = (1.1 * (f64) hlcm->preallocated_lb_config/ (f64) (num_threads - 1));
			for (j = 1; j < num_threads; j++) {
				pool_init_fixed (hlcm->hili_lb_config_pools[j], preallocated_data_per_worker);
			}

		}
	}

}

clib_error_t *
hili_lb_config_enable_disable (vlib_main_t * vm, u8 is_en)
{
	FUNC_TRACE;
	clib_error_t *error = 0;
	if (is_en) {
		if (hili_lb_config_main.is_enabled) {
			LINE_TRACE;
			return 0;
		}
		LINE_TRACE;
		error = hili_lb_config_main_enable (vm);
	} else {
		LINE_TRACE;
	}

	return error;
}


static clib_error_t *
hili_lb_config_config_fn(vlib_main_t * vm, unformat_input_t * input)
{
	hili_lb_config_main_t *hlcm = &hili_lb_config_main;
	u32 nitems;
	uword tmp;
	hlcm->preallocated_lb_config = 0;
	hlcm->default_lb_method = LB_METHOD_HI;
	hlcm->is_enabled = 0;
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "preallocated-lb-config %d", &hlcm->preallocated_lb_config)) 
		; 
		else if (unformat (input, "default-lb-method %d", &hlcm->default_lb_method))
		;
		else
		return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
	}
	if (!hlcm->preallocated_lb_config) {
		hlcm->preallocated_lb_config = 10;
	}
	return 0;
}

VLIB_CONFIG_FUNCTION (hili_lb_config_config_fn, "hililbconfig");


/********LB config end************************/

void
hili_session_set_session_state(session_t *hili_ss, session_state_t new_state)
{
	hili_ss->ss_state_array[hili_ss->cur_state_id++] = hili_ss->session_state;
	hili_ss->session_state = new_state;
}

void
hili_session_stop_tiemr_queues(session_t *hili_ss, session_worker_t *wrk)
{
	FUNC_TRACE;
	TIMER_TAILQ_STOP(hili_ss, wrk->session_pipe_ue_queue, ss_pipe_ue);
	TIMER_TAILQ_STOP(hili_ss, wrk->session_pipe_de_queue, ss_pipe_de);
	TIMER_TAILQ_STOP(hili_ss, wrk->session_ue_queue, session_ue);
	TIMER_TAILQ_STOP(hili_ss, wrk->session_txe_queue, session_txe);
	TIMER_TAILQ_STOP(hili_ss, wrk->session_ptxe_queue, session_ptxe);
	TIMER_TAILQ_STOP(hili_ss, wrk->session_hclosee_queue, session_hclosee);
	TIMER_TAILQ_STOP(hili_ss, wrk->session_terme_queue, session_terme);
}


/**
 * Notify transport the session need terminate right now. 
 */
void
stream_session_terminate_transport (session_t * s)
{
	if (!is_stream_session_hili_proxy_enable()) {
		return;
	}

	hili_session_set_session_state(s, SESSION_STATE_CLOSED);
	if (tp_vfts[session_get_transport_proto (s)].terminate != NULL) {
		tp_vfts[session_get_transport_proto (s)].terminate (s->connection_index,s->thread_index, s->reset_errorcode);
	}
}

/**
 * Notification from transport that peer side connection ready for close.
 *
 * Second FIN mean the first FIN send out by local, and peer side is closing 
 */
void
stream_session_peer_passive_disconnect_notify (transport_connection_t * tc)
{
	application_t *server;
	session_t *s;

	s = session_get (tc->s_index, tc->thread_index);
	if  (is_stream_session_hili_proxy_enable()) {
		hili_session_set_session_state(s, SESSION_STATE_CLOSED);
		if  (s && s->rx_cb_func) {
			s->hili_flags |= SS_TCP_RECV_SECOND_FIN;
			//s->rx_cb_func(s);
			s->read = 1;
			hili_session_raise_event(s, TQ_TYPE_TCP_TOUCH_APP);
		}
	}
}

/**
 * Notification from transport that peer side update the window.
 *
 * When app side want send something,but no window, will wait for this update.
 */
void
stream_session_window_update_notify(transport_connection_t * tc)
{
	session_t *s;

	s = session_get (tc->s_index, tc->thread_index);
	if  (is_stream_session_hili_proxy_enable()) {
		if  (s && s->rx_cb_func && (s->hili_flags & SS_TCP_APPNOWINDOW)) {
			s->write = 1;
			hili_session_raise_event(s, TQ_TYPE_TCP_TOUCH_APP);
			s->hili_flags &= ~SS_TCP_APPNOWINDOW;
		}
	}
}


#define NEWSS_ARCHI 1

#if NEWSS_ARCHI

void
hili_session_tcp_chain_recv_vb(vlib_main_t * vm,session_t *hili_ss, vlib_buffer_t *b)
{
	FUNC_TRACE;
	u32 bi;
	u32 flags, next, len;
	vlib_buffer_t *nb;
	u32 input_vb_len;

	if (b == NULL) {
		LINE_TRACE;
		return;
	}

	bi = vlib_get_buffer_index(vm, b);	


	if (hili_ss->recv_head_b == NULL) {
		hili_ss->recv_head_b = b;
	} else {
		input_vb_len = vlib_buffer_length_in_chain(vm, b);
		hili_ss->recv_head_b->flags |= VLIB_BUFFER_NEXT_PRESENT;
		hili_ss->recv_tail_b->flags |= VLIB_BUFFER_NEXT_PRESENT;
		hili_ss->recv_tail_b->next_buffer = bi;
		b->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
		hili_ss->recv_head_b->total_length_not_including_first_buffer += input_vb_len;

		hili_ss->recv_head_b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
		b->total_length_not_including_first_buffer = 0;
	}

	nb = b;
	do {
		hili_ss->recv_tail_b = nb;
	} while (nb = vlib_get_next_buffer(vm, nb));

}

void
hili_session_tcp_chain_send_vb(vlib_main_t * vm,session_t *hili_ss, vlib_buffer_t *b)
{
	FUNC_TRACE;
	u32 bi;
 	u32 flags, next, len, b_chain_len;
	vlib_buffer_t *nb;

	if (b == NULL) {
		LINE_TRACE;
		return;
	}

	b_chain_len = vlib_buffer_length_in_chain(vm, b);
	bi = vlib_get_buffer_index(vm, b);	


	if (hili_ss->send_head_b == NULL) {
		hili_ss->send_head_b = b;
	} else {
		hili_ss->send_head_b->flags |= VLIB_BUFFER_NEXT_PRESENT;
		hili_ss->send_tail_b->flags |= VLIB_BUFFER_NEXT_PRESENT;
		hili_ss->send_tail_b->next_buffer = bi;
		b->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
		hili_ss->send_head_b->total_length_not_including_first_buffer += b_chain_len;
		hili_ss->send_head_b->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
		b->total_length_not_including_first_buffer = 0;
	}

	nb = b;
	do {
		hili_ss->send_tail_b = nb;
	} while (nb = vlib_get_next_buffer(vm, nb));

	session_exchange_print("The caculate len : %d", hili_ss->send_head_b->current_length + hili_ss->send_head_b->total_length_not_including_first_buffer);
	session_log_debug("The caculate len : %d", hili_ss->send_head_b->current_length + hili_ss->send_head_b->total_length_not_including_first_buffer);
	DEBUG_DUMP_SESSION_VLIB_BUFFER("Send head chain after add buffer to head", hili_ss->send_head_b);

}

int
hili_session_enqueue_stream_connection(transport_connection_t * tc, vlib_buffer_t * orig_b)
{
	//SESSION_FUNC_TRACE;
	vlib_buffer_t *b = NULL;
	u32 total_len;
	u32 total_input_len;
	session_t *s;
	vlib_main_t *vm = vlib_get_main ();

	if (use_copy_when_recv) {
		b = hili_vlib_buffer_copy(vm, orig_b, 1000);
	} else {
		b = orig_b;
	}

	total_input_len = b->current_length;
	if (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID) {
		total_input_len += b->total_length_not_including_first_buffer;
	}

	session_exchange_print("Self caculate the total input len : %d", total_input_len);
	session_log_debug("Self caculate the total input len : %d", total_input_len);
	DEBUG_DUMP_SESSION_VLIB_BUFFER("Input vlib", b);

	s = session_get (tc->s_index, tc->thread_index);
	hili_session_enqueue_stream_try_assemble_packet(s, b);

	//session_exchange_print("Self caculate the total input len : %d", total_input_len);
	DEBUG_DUMP_SESSION_VLIB_BUFFER("After assemble", b);

	if (s->recv_head_b != NULL) {
		DEBUG_DUMP_SESSION_VLIB_BUFFER("Before chain recv_head_b", s->recv_head_b);
	}

#if 0
	if (total_input_len < 1448 && total_input_len > 1200) {
		hili_buffer_set_trace_flag(b);
	}
#endif

	ft_printf("session s addres : %p\n", s);
	hili_session_tcp_chain_recv_vb(vm, s, b);

	total_len = s->recv_head_b->current_length;
	if (s->recv_head_b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID) {
		total_len += s->recv_head_b->total_length_not_including_first_buffer;
	}

	session_exchange_print("Self caculate the total len after chain : %d", total_len);
	session_log_debug("Self caculate the total len after chain : %d", total_len);
	DEBUG_DUMP_SESSION_VLIB_BUFFER("After chain recv_head_b", s->recv_head_b);

	return total_input_len;
}

always_inline void
hili_session_ooo_dump_reass_queue(vlib_main_t *vm, session_t *s)
{
	vlib_buffer_t *cur_vb;

	if (s->reass_head_b == NULL) {
		tcp_reass_print("reass_head_b is NULL and return");
		return;
	}

	if (debug_tcp_reass != 1) {
		return;
	}

	tcp_reass_print("All the segment in reass queue:");
	for (cur_vb = s->reass_head_b; cur_vb; ) {
		tcp_reass_print("seq %u		seq_end %u 		data_len %u",
			vnet_buffer(cur_vb)->tcp.seq_number, vnet_buffer(cur_vb)->tcp.seq_end,
				vnet_buffer(cur_vb)->tcp.data_len);

		/*Get next reass packet*/
		if (vnet_buffer2(cur_vb)->reass_vb_flags & REASS_VB_NEXT_PKT) {
			cur_vb = vlib_get_buffer(vm, vnet_buffer2(cur_vb)->reass_next_vb);
		} else {
			cur_vb = NULL;
		}
	}

}
void
hili_session_enqueue_stream_try_assemble_packet(session_t *s, vlib_buffer_t *vb)
{
	tcp_reass_print("Enter");
	vlib_main_t *vm = vlib_get_main ();
	vlib_buffer_t *cur_vb;

	tcp_reass_print("Input vb begine with seq %u and end seq %u", vnet_buffer(vb)->tcp.seq_number, vnet_buffer(vb)->tcp.seq_end);
	if (s->reass_head_b == NULL) {
		tcp_reass_print("reass_head_b is NULL and return");
		return;
	} else {
		hili_session_ooo_dump_reass_queue(vm, s);
		if (seq_geq(vnet_buffer(vb)->tcp.seq_end, vnet_buffer(s->reass_head_b)->tcp.seq_number)) {
			/*收到的vb geq 当前重组队列的第�?个vb，则说明至少可以尝试组装这个队列头vb*/
			/*Like vb is 3,4,5,6 (tcp.seq_end �?7)  head is 7,8,9  */
			while (s->reass_head_b) {
				cur_vb = s->reass_head_b;
				tcp_reass_print("cur_vb seq %u, input vb seq_end %u", vnet_buffer(cur_vb)->tcp.seq_number,
					vnet_buffer(vb)->tcp.seq_end);
				if (seq_lt(vnet_buffer(cur_vb)->tcp.seq_number, vnet_buffer(vb)->tcp.seq_end)) {
					/*当前段的起始seq < 收到报文的seq_end*/
					/*like ---------- 收到报文
						    --- 队列中的当前�?*/
					if (seq_leq(vnet_buffer(cur_vb)->tcp.seq_end, vnet_buffer(vb)->tcp.seq_end)) {
						tcp_reass_print("input vb totaly cover the current queued segment");
						if (vnet_buffer2(cur_vb)->reass_vb_flags & REASS_VB_NEXT_PKT) {
							s->reass_head_b = vlib_get_buffer(vm, vnet_buffer2(cur_vb)->reass_next_vb);
						} else {
							s->reass_head_b = NULL;
						}
						vlib_buffer_hili_free_one_buffer(vm, cur_vb);
						continue;
					} else {
						/*like ---------- 收到报文vb
							     ------------ cur_vb队列中的当前�?*/
						tcp_reass_print("input vb right overlapping with current queued segment");
						if (vlib_buffer_hili_trim(vm, vb, (vnet_buffer(vb)->tcp.seq_end - vnet_buffer(cur_vb)->tcp.seq_number))) {
							return;
						} else {
							vnet_buffer(vb)->tcp.data_len = vnet_buffer(cur_vb)->tcp.seq_number - vnet_buffer(vb)->tcp.seq_number;
							vnet_buffer(vb)->tcp.seq_end = vnet_buffer(vb)->tcp.seq_number + vnet_buffer(vb)->tcp.data_len;
						}
						tcp_reass_print("After input vb trimed, data len %u, seq %u, seq_end %u",
							vnet_buffer(vb)->tcp.data_len, vnet_buffer(vb)->tcp.seq_number, vnet_buffer(vb)->tcp.seq_end);
					}
				}

				if (vnet_buffer(cur_vb)->tcp.seq_number == vnet_buffer(vb)->tcp.seq_end) {
					if (vnet_buffer2(cur_vb)->reass_vb_flags & REASS_VB_NEXT_PKT) {
						s->reass_head_b = vlib_get_buffer(vm, vnet_buffer2(cur_vb)->reass_next_vb);
					} else {
						s->reass_head_b = NULL;
					}

					tcp_reass_print("Input segment info:");
					tcp_reass_print("Start seq %u, end seq %u, data_len %u",
						vnet_buffer(vb)->tcp.seq_number, vnet_buffer(vb)->tcp.seq_end, vnet_buffer(vb)->tcp.data_len);
					tcp_reass_print("Current segment info:");
					tcp_reass_print("Start seq %u, end seq %u, data_len %u",
						vnet_buffer(cur_vb)->tcp.seq_number, vnet_buffer(cur_vb)->tcp.seq_end, vnet_buffer(cur_vb)->tcp.data_len);
					vnet_buffer(vb)->tcp.data_len += vnet_buffer(cur_vb)->tcp.data_len;
					vnet_buffer(vb)->tcp.seq_end = vnet_buffer(cur_vb)->tcp.seq_end;

					tcp_reass_print("Input vb : after assemble curr seg:");
					tcp_reass_print("Start seq %u, end seq %u, data_len %u",
						vnet_buffer(vb)->tcp.seq_number, vnet_buffer(vb)->tcp.seq_end, vnet_buffer(vb)->tcp.data_len);

					if (vnet_buffer(vb)->tcp.seq_end != (vnet_buffer(vb)->tcp.data_len + vnet_buffer(vb)->tcp.seq_number)) {
						tcp_reass_print("something wrong !!!!!");
					}
					vnet_buffer2(cur_vb)->reass_vb_flags &= ~REASS_VB_NEXT_PKT;
					vlib_buffer_hili_chain(vm, vb, cur_vb);

					tcp_reass_print("The length after buffer chain together %u", vlib_buffer_length_in_chain(vm, vb));
					hili_session_ooo_dump_reass_queue(vm, s);
				} else {
					return;
				}
			}
			s->reass_tail_b = NULL;
			return;
		}
	}
	hili_session_ooo_dump_reass_queue(vm, s);
}


/*Return 0 if sucess enqueue
 *Return -1 if failed
 */
int
hili_session_enqueue_stream_connection_ooo(session_t * s, vlib_buffer_t * orig_b)
{
	tcp_reass_print("Enter");
	vlib_buffer_t *b = NULL;
	vlib_buffer_t *cur_vb;
	vlib_buffer_t *prev_vb = NULL;
	u32 total_len;
	u32 total_input_len;
	vlib_main_t *vm = vlib_get_main ();

	if (1 && use_copy_when_recv) {
		b = hili_vlib_buffer_copy(vm, orig_b, 1000);
	} else {
		b = orig_b;
	}

	total_input_len = b->current_length;
	if (b->flags & VLIB_BUFFER_TOTAL_LENGTH_VALID) {
		total_input_len += b->total_length_not_including_first_buffer;
	}
	tcp_reass_print("Self caculate the total input len : %d", total_input_len);
	//DEBUG_DUMP_TCP_REASS_VLIB_BUFFER("Input vlib", b);

	tcp_reass_print("intput vb begine with seq %u and end seq %u", vnet_buffer(b)->tcp.seq_number, vnet_buffer(b)->tcp.seq_end);
	if (s->reass_head_b == NULL) {
		tcp_reass_print("reass head is NULL so just point to the first vb");
		s->reass_head_b = s->reass_tail_b = b;
		return 0;
	} else {
		tcp_reass_print("The ooo queue tail segment begin with %u, end with %u",
			vnet_buffer(s->reass_tail_b)->tcp.seq_number, vnet_buffer(s->reass_tail_b)->tcp.seq_end);
		if (seq_leq(vnet_buffer(s->reass_tail_b)->tcp.seq_end, vnet_buffer(b)->tcp.seq_number)) {
			/*The input vb with the largest the seq number, so insert to tail*/
			tcp_reass_print("Just insert the input vb to tail");
			vnet_buffer2(s->reass_tail_b)->reass_next_vb = vlib_get_buffer_index(vm, b);
			vnet_buffer2(s->reass_tail_b)->reass_vb_flags |= REASS_VB_NEXT_PKT;
			s->reass_tail_b = b;
		} else {
			for (cur_vb = s->reass_head_b; cur_vb; ) {
				if (seq_gt(vnet_buffer(cur_vb)->tcp.seq_number, vnet_buffer(b)->tcp.seq_number)) {
					if (seq_gt(vnet_buffer(b)->tcp.seq_end, vnet_buffer(cur_vb)->tcp.seq_number)) {
						/*右侧重叠case: It's like vb is 3, 4, 5, and cur is 4,5,6,7*/
						tcp_reass_print("It's right overlapping case");
						tcp_reass_print("input vb seq %u, end seq %u", vnet_buffer(b)->tcp.seq_number, vnet_buffer(b)->tcp.seq_end);
						tcp_reass_print("current vb seq %u, end seq %u", vnet_buffer(cur_vb)->tcp.seq_number, vnet_buffer(cur_vb)->tcp.seq_end);
						vlib_buffer_hili_free_one_buffer(vm, b);
					} else if (prev_vb && seq_gt(vnet_buffer(prev_vb)->tcp.seq_end, vnet_buffer(b)->tcp.seq_number)) {
						/*左侧重叠case: It's like: prev is 3,4,5; b is 4,5,6 and cur vb is 8,9,10*/
						tcp_reass_print("It's left overlapping case");
						tcp_reass_print("input vb seq %u, end seq %u", vnet_buffer(b)->tcp.seq_number, vnet_buffer(b)->tcp.seq_end);
						tcp_reass_print("prev  vb seq %u, end seq %u", vnet_buffer(cur_vb)->tcp.seq_number, vnet_buffer(cur_vb)->tcp.seq_end);

						vlib_buffer_hili_free_one_buffer(vm, b);
					} else {
						/*It's good case like: pre is 3,4,5; b is 7,8,9; cur_vb is 12,13,14*/
						tcp_reass_print("good case");
						tcp_reass_print("Insert segment with seq %u at front of segment with seq %u",
								vnet_buffer(b)->tcp.seq_number, vnet_buffer(cur_vb)->tcp.seq_number);
						if (prev_vb == NULL) {
							s->reass_head_b = b;
							vnet_buffer2(b)->reass_next_vb = vlib_get_buffer_index(vm, cur_vb);
							vnet_buffer2(b)->reass_vb_flags |= REASS_VB_NEXT_PKT;
						} else {
							vnet_buffer2(b)->reass_next_vb = vnet_buffer2(prev_vb)->reass_next_vb;
							vnet_buffer2(b)->reass_vb_flags |= REASS_VB_NEXT_PKT;
							vnet_buffer2(prev_vb)->reass_next_vb = vlib_get_buffer_index(vm, b);
						}
					}
					return 0;
				}

				prev_vb = cur_vb;
				if (vnet_buffer2(cur_vb)->reass_vb_flags & REASS_VB_NEXT_PKT) {
					cur_vb = vlib_get_buffer(vm, vnet_buffer2(cur_vb)->reass_next_vb);
				} else {
					cur_vb = NULL;
				}
			}
			/*duplicate packet, just free it*/
			vlib_buffer_hili_free_one_buffer(vm, b);
		}
	}

	return 0;
}

#endif

uword
tp_unformat_vnet_uri(unformat_input_t * input, va_list * args)
{
  session_endpoint_cfg_t *sep = va_arg (*args, session_endpoint_cfg_t *);
  u32 transport_proto = 0, port;

  sep->sw_if_index = ((u32)~0);
  sep->peer.sw_if_index = ((u32)~0);
  if (unformat (input, "%U://%U/%d", unformat_transport_proto,
		&transport_proto, unformat_ip4_address, &sep->ip.ip4, &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 1;
      return 1;
    }
  else if (unformat (input, "%U://[%s]%U/%d", unformat_transport_proto,
		     &transport_proto, &sep->hostname, unformat_ip4_address,
		     &sep->ip.ip4, &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 1;
      return 1;
    }
  else if (unformat (input, "%U://%U/%d", unformat_transport_proto,
		     &transport_proto, unformat_ip6_address, &sep->ip.ip6,
		     &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 0;
      return 1;
    }
  else if (unformat (input, "%U://[%s]%U/%d", unformat_transport_proto,
		     &transport_proto, &sep->hostname, unformat_ip6_address,
		     &sep->ip.ip6, &port))
    {
      sep->transport_proto = transport_proto;
      sep->port = clib_host_to_net_u16 (port);
      sep->is_ip4 = 0;
      return 1;
    }
  return 0;
}


int
tp_parse_uri (char *uri, session_endpoint_t * sep)
{
	unformat_input_t _input, *input = &_input;

	/* Make sure */
	uri = (char *) format (0, "%s%c", uri, 0);

	/* Parse uri */
	unformat_init_string (input, uri, strlen (uri));
	if (!unformat (input, "%U", tp_unformat_vnet_uri, sep)) {
		unformat_free (input);
		return VNET_API_ERROR_INVALID_VALUE;
	}
	unformat_free (input);

  return 0;
}
#if 0
always_inline int
session_listen_vc (session_t * ls, session_endpoint_t * sep)
{
  transport_connection_t *tc;
  u32 tci;

  /* Transport bind/listen  */
  tci = tp_vfts[sep->transport_proto].bind (s->session_index,
					    session_endpoint_to_transport
					    (sep));

  if (tci == (u32) ~ 0)
    return -1;

  /* Attach transport to session */
  s->connection_index = tci;
  tc = tp_vfts[sep->transport_proto].get_listener (tci);

  /* Weird but handle it ... */
  if (tc == 0)
    return -1;

  /* Add to the main lookup table */
  session_lookup_add_connection (tc, s->session_index);
  return 0;
}
#endif

#if 0
static int
l4proxy_reverse_server_create(vlib_main_t * vm, u32 lb_config_index) {
	FUNC_TRACE;
	hili_lb_config_t *lbp = hili_lb_config_get(lb_config_index, vm->thread_index);
	session_t *s;
	session_handle_t lh;
	session_type_t sst;
	session_endpoint_t *sep = &lbp->server_sep;
	transport_connection_t *tc;
	
	sst = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);
	s = listen_session_alloc (0, sst);
	s->app_index = ~0;
	s->hili_extflags |= SS_EXTFLAG_TLSPROXY;
	s->opaque = lb_config_index;
	s->rx_cb_func = l4app_proxy_start;
	if (session_listen (s, sep)) {
		LINE_TRACE;
		printf("Failed to call stream_session_listen\n");
	}
	tc = session_get_transport(s);
	lh = listen_session_get_handle(s);
	session_lookup_add_connection (tc, lh);
}

static clib_error_t *
l4proxy_reverse_server_create_command_fn(vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
	char *default_server_uri = "tcp://0.0.0.0/23";
	char *default_client_uri = "tcp://6.0.2.2/23";
	int rv;
	u64 tmp;
	hili_lb_config_t *lbp;

	hili_lb_config_enable_disable(vm, 1);
	lbp = hili_lb_config_alloc(vm->thread_index);

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "vs-uri %s", &lbp->server_uri)) {
			;
	    } else if (unformat (input, "rs-uri %s", &lbp->client_uri)) {
			lbp->client_uri = format (0, "%s%c", lbp->client_uri, 0);
	    } else if (unformat (input, "lb-name %s", &lbp->lb_name)) {
			;
		} else {
			return clib_error_return (0, "unknown input `%U'",
						  format_unformat_error, input);
	    }
    }

	if (!tlsproxy_license_setup_and_lookup()) {
		return clib_error_return(0, "please get the tlsproxy license first.", input);
	}

	if (!lbp->server_uri) {
		clib_warning ("No vs-uri provided, Using default: %s",default_server_uri);
		lbp->server_uri = format (0, "%s%c", default_server_uri, 0);
	}
	
	if (!lbp->client_uri) {
		clib_warning ("No rs-uri provided, Using default: %s", default_client_uri);
		lbp->client_uri = format (0, "%s%c", default_client_uri, 0);
	}
	tp_parse_uri(lbp->server_uri, &lbp->server_sep);
	tp_parse_uri(lbp->client_uri, &lbp->client_sep);

	vnet_session_enable_disable (vm, 1 /* turn on session and transport */ );
	lbp->vs_type = HILI_LB_TCP_VS;
	lbp->rs_type = HILI_LB_TCP_RS;
	rv = l4proxy_reverse_server_create (vm, lbp->hili_lb_config_index);
	switch (rv)
	{
	case 0:
	  break;
	default:
	  return clib_error_return (0, "server_create returned %d", rv);
	}

	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (l4proxy_reverse_create_command, static) =
{
  .path = "l4proxy reverse static",
  .short_help = "l4proxy reverse static lb-name <lbname> [vs-uri <tcp://listen-ip/port>]"
      "[rs-uri <tcp://rs-ip/port>]",
  .function = l4proxy_reverse_server_create_command_fn,
};
/* *INDENT-ON* */

static int
tls_forward_proxy_server_create(vlib_main_t * vm, u32 lb_config_index) {
	FUNC_TRACE;
	//hili_lb_config_t *lbp = &tlsproxy_main;
	hili_lb_config_t *lbp = hili_lb_config_get(lb_config_index, vm->thread_index);
	session_t *s;
	session_handle_t lh;
	session_type_t sst;
	session_endpoint_t *sep = &lbp->server_sep;
	transport_connection_t *tc;
	
	sst = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);
	s = listen_session_alloc (0, sst);
	s->app_index = ~0;
	s->hili_extflags |= SS_EXTFLAG_TLSPROXY;
	s->opaque = lb_config_index;
	s->rx_cb_func = l4app_proxy_start;
	if (session_listen (s, sep)) {
		LINE_TRACE;
		printf("Failed to call stream_session_listen\n");
	}
	tc = session_get_transport(s);
	lh = listen_session_get_handle(s);
	session_lookup_add_connection (tc, lh);
}


static clib_error_t *
tls_forward_proxy_server_create_command_fn(vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
	char *default_server_uri = "tcp://0.0.0.0/443";
	char *default_client_uri = "tcp://192.168.169.136/80";
	int rv;
	u64 tmp;
	hili_lb_config_t *lbp;

	hili_lb_config_enable_disable(vm, 1);
	lbp = hili_lb_config_alloc(vm->thread_index);

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "vs-uri %s", &lbp->server_uri)) {
			;
	    } else if (unformat (input, "rs-uri %s", &lbp->client_uri)) {
			lbp->client_uri = format (0, "%s%c", lbp->client_uri, 0);
		} else if (unformat (input, "lb-name %s", &lbp->lb_name)) {
			;
	    } else {
			return clib_error_return (0, "unknown input `%U'",
						  format_unformat_error, input);
	    }
    }

	if (!tlsproxy_license_setup_and_lookup()) {
		return clib_error_return(0, "please get the tlsproxy license first.", input);
	}

	if (!lbp->server_uri) {
		clib_warning ("No vs-uri provided, Using default: %s",default_server_uri);
		lbp->server_uri = format (0, "%s%c", default_server_uri, 0);
	}

	if (!lbp->client_uri) {
		clib_warning ("No rs-uri provided, Using default: %s", default_client_uri);
		lbp->client_uri = format (0, "%s%c", default_client_uri, 0);
	}
	tp_parse_uri(lbp->server_uri, &lbp->server_sep);
	tp_parse_uri(lbp->client_uri, &lbp->client_sep);

	vnet_session_enable_disable (vm, 1 /* turn on session and transport */ );

	hili_tlsproxy_enable_disable(vm, 1);
	lbp->vs_type = HILI_LB_TCP_VS;
	lbp->rs_type = HILI_LB_TLS_RS;

	rv = tls_forward_proxy_server_create (vm, lbp->hili_lb_config_index);
	switch (rv)
	{
	case 0:
	  break;
	default:
	  return clib_error_return (0, "server_create returned %d", rv);
	}

	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tls_forward_proxy_create_command, static) =
{
  .path = "tlsproxy forward static",
  .short_help = "tlsproxy forward static lb-name <lbname> [vs-uri <tcp://listen-ip/port>]"
      "[rs-uri <tcp://rs-ip/port>]",
  .function = tls_forward_proxy_server_create_command_fn,
};
/* *INDENT-ON* */


static int
tls_reverse_proxy_server_create(vlib_main_t * vm, u32 lb_config_index) {
	FUNC_TRACE;
	//hili_lb_config_t *lbp = &tlsproxy_main;
	hili_lb_config_t *lbp = hili_lb_config_get(lb_config_index, vm->thread_index);
	session_t *s;
	session_handle_t lh;
	session_type_t sst;
	session_endpoint_t *sep = &lbp->server_sep;
	transport_connection_t *tc;
	
	sst = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);
	s = listen_session_alloc (0, sst);
	s->app_index = ~0;
	s->hili_extflags |= SS_EXTFLAG_TLSPROXY;
	s->opaque = lb_config_index;
	s->rx_cb_func = tls_server_stack_start;
	if (session_listen (s, sep)) {
		LINE_TRACE;
		printf("Failed to call stream_session_listen\n");
	}
	tc = session_get_transport(s);
	lh = listen_session_get_handle(s);
	session_lookup_add_connection (tc, lh);
}


static clib_error_t *
tls_reverse_proxy_server_create_command_fn(vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
	char *default_server_uri = "tcp://0.0.0.0/443";
	char *default_client_uri = "tcp://192.168.169.136/80";
	int rv;
	u64 tmp;
	hili_lb_config_t *lbp;

	hili_lb_config_enable_disable(vm, 1);
	lbp = hili_lb_config_alloc(vm->thread_index);

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "vs-uri %s", &lbp->server_uri)) {
			;
	    } else if (unformat (input, "rs-uri %s", &lbp->client_uri)) {
			lbp->client_uri = format (0, "%s%c", lbp->client_uri, 0);
		} else if (unformat (input, "lb-name %s", &lbp->lb_name)) {
			;
	    } else {
			return clib_error_return (0, "unknown input `%U'",
						  format_unformat_error, input);
	    }
    }

	if (!tlsproxy_license_setup_and_lookup()) {
		return clib_error_return(0, "please get the tlsproxy license first.", input);
	}

	if (!lbp->server_uri) {
		clib_warning ("No vs-uri provided, Using default: %s",default_server_uri);
		lbp->server_uri = format (0, "%s%c", default_server_uri, 0);
	}

	if (!lbp->client_uri) {
		clib_warning ("No rs-uri provided, Using default: %s", default_client_uri);
		lbp->client_uri = format (0, "%s%c", default_client_uri, 0);
	}
	tp_parse_uri(lbp->server_uri, &lbp->server_sep);
	tp_parse_uri(lbp->client_uri, &lbp->client_sep);

	vnet_session_enable_disable (vm, 1 /* turn on session and transport */ );

	hili_tlsproxy_enable_disable(vm, 1);
	lbp->vs_type = HILI_LB_TLS_VS;
	lbp->rs_type = HILI_LB_TCP_RS;

	rv = tls_reverse_proxy_server_create (vm, lbp->hili_lb_config_index);
	switch (rv)
	{
	case 0:
	  break;
	default:
	  return clib_error_return (0, "server_create returned %d", rv);
	}

	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tls_reverse_proxy_create_command, static) =
{
  .path = "tlsproxy reverse static",
  .short_help = "tlsproxy reverse static lb-name <lbname> [vs-uri <tcp://listen-ip/port>]"
      "[rs-uri <tcp://rs-ip/port>]",
  .function = tls_reverse_proxy_server_create_command_fn,
};
/* *INDENT-ON* */


static int
tls_bidirectional_proxy_server_create(vlib_main_t * vm, u32 lb_config_index) {
	FUNC_TRACE;
	hili_lb_config_t *lbp = hili_lb_config_get(lb_config_index, vm->thread_index);
	session_t *s;
	session_handle_t lh;
	session_type_t sst;
	session_endpoint_t *sep = &lbp->server_sep;
	transport_connection_t *tc;
	
	sst = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);
	s = listen_session_alloc (0, sst);
	s->app_index = ~0;
	s->hili_extflags |= SS_EXTFLAG_TLSPROXY;
	s->opaque = lb_config_index;
	s->rx_cb_func = tls_server_stack_start;
	if (session_listen (s, sep)) {
		LINE_TRACE;
		printf("Failed to call stream_session_listen\n");
	}
	tc = session_get_transport(s);
	lh = listen_session_get_handle(s);
	session_lookup_add_connection (tc, lh);
}

static clib_error_t *
tls_bidirectional_proxy_server_create_command_fn(vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
	char *default_server_uri = "tcp://0.0.0.0/443";
	char *default_client_uri = "tcp://192.168.169.136/80";
	int rv;
	u64 tmp;
	hili_lb_config_t *lbp;

	hili_lb_config_enable_disable(vm, 1);
	lbp = hili_lb_config_alloc(vm->thread_index);

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "vs-uri %s", &lbp->server_uri)) {
			;
	    } else if (unformat (input, "rs-uri %s", &lbp->client_uri)) {
			lbp->client_uri = format (0, "%s%c", lbp->client_uri, 0);
		} else if (unformat (input, "lb-name %s", &lbp->lb_name)) {
			;
	    } else {
			return clib_error_return (0, "unknown input `%U'",
						  format_unformat_error, input);
	    }
    }

	if (!tlsproxy_license_setup_and_lookup()) {
		return clib_error_return(0, "please get the tlsproxy license first.", input);
	}

	if (!lbp->server_uri) {
		clib_warning ("No vs-uri provided, Using default: %s",default_server_uri);
		lbp->server_uri = format (0, "%s%c", default_server_uri, 0);
	}

	if (!lbp->client_uri) {
		clib_warning ("No rs-uri provided, Using default: %s", default_client_uri);
		lbp->client_uri = format (0, "%s%c", default_client_uri, 0);
	}
	tp_parse_uri(lbp->server_uri, &lbp->server_sep);
	tp_parse_uri(lbp->client_uri, &lbp->client_sep);

	vnet_session_enable_disable (vm, 1 /* turn on session and transport */ );

	hili_tlsproxy_enable_disable(vm, 1);
	lbp->vs_type = HILI_LB_TLS_VS;
	lbp->rs_type = HILI_LB_TLS_RS;

	rv = tls_bidirectional_proxy_server_create (vm, lbp->hili_lb_config_index);
	switch (rv)
	{
	case 0:
	  break;
	default:
	  return clib_error_return (0, "server_create returned %d", rv);
	}

	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (tls_bidirectional_proxy_create_command, static) =
{
  .path = "tlsproxy bidirectional static",
  .short_help = "tlsproxy bidirectional static lb-name <lbname> [vs-uri <tcp://listen-ip/port>]"
      "[rs-uri <tcp://rs-ip/port>]",
  .function = tls_bidirectional_proxy_server_create_command_fn,
};
/* *INDENT-ON* */
#endif

static int
http_reverse_proxy_virt_server_create(vlib_main_t * vm, u32 lb_config_index) {
	FUNC_TRACE;
	//hili_lb_config_t *lbp = &tlsproxy_main;
	hili_lb_config_t *lbp = hili_lb_config_get(lb_config_index, vm->thread_index);
	session_t *s;
	session_handle_t lh;
	session_type_t sst;
	session_endpoint_t *sep = &lbp->server_sep;
	transport_connection_t *tc;
	
	sst = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);
	s = listen_session_alloc (0, sst);
	s->app_index = ~0;
	s->hili_extflags |= SS_EXTFLAG_TLSPROXY;
	s->opaque = lb_config_index;
	s->rx_cb_func = dproxy_http_input;
	if (session_listen (s, sep)) {
		LINE_TRACE;
		printf("Failed to call stream_session_listen\n");
	}
	tc = session_get_transport(s);
	lh = listen_session_get_handle(s);
	session_lookup_add_connection (tc, lh);
}

static clib_error_t *
http_reverse_proxy_virt_server_create_command_fn(vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
	char *default_server_uri = "tcp://0.0.0.0/80";
	char *default_client_uri = "tcp://192.168.169.136/80";
	int rv;
	u64 tmp;
	hili_lb_config_t *lbp;

	hili_lb_config_enable_disable(vm, 1);
	lbp = hili_lb_config_alloc(vm->thread_index);

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "vs-uri %s", &lbp->server_uri)) {
			;
	    } else if (unformat (input, "rs-uri %s", &lbp->client_uri)) {
			lbp->client_uri = format (0, "%s%c", lbp->client_uri, 0);
		} else if (unformat (input, "lb-name %s", &lbp->lb_name)) {
			;
	    } else {
			return clib_error_return (0, "unknown input `%U'",
						  format_unformat_error, input);
	    }
    }

	if (!lbp->server_uri) {
		clib_warning ("No vs-uri provided, Using default: %s",default_server_uri);
		lbp->server_uri = format (0, "%s%c", default_server_uri, 0);
	}

	if (!lbp->client_uri) {
		clib_warning ("No rs-uri provided, Using default: %s", default_client_uri);
		lbp->client_uri = format (0, "%s%c", default_client_uri, 0);
	}
	tp_parse_uri(lbp->server_uri, &lbp->server_sep);
	tp_parse_uri(lbp->client_uri, &lbp->client_sep);

	vnet_session_enable_disable (vm, 1 /* turn on session and transport */ );

	hili_htproxy_enable_disable(vm, 1);
	lbp->vs_type = HILI_LB_TCP_VS;
	lbp->rs_type = HILI_LB_TCP_RS;

	rv = http_reverse_proxy_virt_server_create (vm, lbp->hili_lb_config_index);
	switch (rv)
	{
	case 0:
	  break;
	default:
	  return clib_error_return (0, "server_create returned %d", rv);
	}

	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (http_reverse_proxy_create_command, static) =
{
  .path = "htproxy reverse static",
  .short_help = "htproxy reverse static lb-name <lbname> [vs-uri <tcp://listen-ip/port>]"
      "[rs-uri <tcp://rs-ip/port>]",
  .function = http_reverse_proxy_virt_server_create_command_fn,
};
/* *INDENT-ON* */

void
hili_session_cleanup(session_t *hili_ss)
{
	session_main_t *smm = vnet_get_session_main ();
	vlib_main_t *vm = vlib_get_main();

	u32 tid = hili_ss->thread_index;

	session_worker_t *wrk = &smm->wrk[tid];

	hili_session_stop_tiemr_queues(hili_ss, wrk);

	if (hili_ss->recv_head_b != NULL) {
		vlib_buffer_hili_free_one_buffer(vm, hili_ss->recv_head_b);
	}
	hili_ss->recv_head_b = hili_ss->recv_tail_b = NULL;

	if (hili_ss->send_head_b != NULL) {
		vlib_buffer_hili_free_one_buffer(vm, hili_ss->send_head_b);
	}
	hili_ss->send_head_b = hili_ss->send_tail_b = NULL;

	if (hili_ss->reass_head_b != NULL) {
		vlib_buffer_hili_free_one_buffer(vm, hili_ss->reass_head_b);
	}
	hili_ss->reass_head_b = hili_ss->reass_tail_b = NULL;
	if (hili_ss->clenup_cb_func) {
		hili_ss->clenup_cb_func(hili_ss);
	}
}

always_inline void
hili_add_session_to_pipe_dq(session_worker_t *wrk, session_t *hili_ss)
{
	if (!TIMER_ACTIVE(hili_ss, ss_pipe_de)) {
		TAILQ_INSERT_TAIL(&wrk->session_pipe_de_queue, hili_ss, ss_pipe_de);
	}
}

always_inline void
hili_add_session_to_pipe_uq(session_worker_t *wrk, session_t *hili_ss)
{
	if (!TIMER_ACTIVE(hili_ss, ss_pipe_ue)) {
		TAILQ_INSERT_TAIL(&wrk->session_pipe_ue_queue, hili_ss, ss_pipe_ue);
	}
}

always_inline void
hili_add_session_to_tcp_uq(session_worker_t *wrk, session_t *hili_ss)
{
	if (!TIMER_ACTIVE(hili_ss, session_ue)) {
		TAILQ_INSERT_TAIL(&wrk->session_ue_queue, hili_ss, session_ue);
	}
}

always_inline void
hili_add_session_to_tcp_hcloseq(session_worker_t *wrk, session_t *hili_ss)
{
	if (!TIMER_ACTIVE(hili_ss, session_hclosee)) {
		TAILQ_INSERT_TAIL(&wrk->session_hclosee_queue, hili_ss, session_hclosee);
	}
}

always_inline void
hili_add_session_to_tcp_termq(session_worker_t *wrk, session_t *hili_ss)
{
	if (!TIMER_ACTIVE(hili_ss, session_terme)) {
		TAILQ_INSERT_TAIL(&wrk->session_terme_queue, hili_ss, session_terme);
	}
}

void
hili_add_session_to_tcp_txq(session_worker_t *wrk, session_t *hili_ss)
{
	if (!TIMER_ACTIVE(hili_ss, session_txe)) {
		TAILQ_INSERT_TAIL(&wrk->session_txe_queue, hili_ss, session_txe);
	}
}

/*Called by session node*/
void
hili_add_session_to_tcp_pending_txq(session_worker_t *wrk, session_t *hili_ss)
{
	if (hili_ss->session_state >= SESSION_STATE_TRANSPORT_CLOSED) {
		session_node_print("The TCP and session are declining, just return");
		return;
	}

	if (!TIMER_ACTIVE(hili_ss, session_ptxe)) {
		TAILQ_INSERT_TAIL(&wrk->session_ptxe_queue, hili_ss, session_ptxe);
	}
}

void
hili_session_raise_event(session_t *hili_ss, hili_tq_type_t tqt)
{
	u32 thread_index = vlib_get_thread_index ();
	session_main_t *smm = vnet_get_session_main ();
	session_worker_t *wrk;

	if (!hili_ss) {
		return;
	}

	ASSERT (hili_ss->thread_index == thread_index || thread_index == 0);

	wrk = &smm->wrk[thread_index];
	switch (tqt)
	{
		case TQ_TYPE_PIPE_DEL:
			hili_add_session_to_pipe_dq(wrk, hili_ss);
			break;
		case TQ_TYPE_TCP_CTRL_HALF_CLOSE:
			hili_add_session_to_tcp_hcloseq(wrk, hili_ss);
			break;
		case TQ_TYPE_TCP_CTRL_TERMINATE:
			hili_add_session_to_tcp_termq(wrk, hili_ss);
			break;
		case TQ_TYPE_TCP_CTRL_TX:
			hili_add_session_to_tcp_txq(wrk, hili_ss);
			break;

		case TQ_TYPE_PIPE_TOUCH_APP:
			hili_add_session_to_pipe_uq(wrk, hili_ss);
			break;
		case TQ_TYPE_TCP_TOUCH_APP:
			hili_add_session_to_tcp_uq(wrk, hili_ss);
			break;
		default:
			printf("Dont' support TQ queue!!!\n");
	}
}

int hili_proxy_enabled = 1;

int
vnet_session_hiliproxy_enable_disable (vlib_main_t * vm, u8 is_en)
{
	FUNC_TRACE;
	if (is_en) {
		if (hili_proxy_enabled == 1) {
			return 1;
		} else {
			hili_proxy_enabled = 1;
		}
	} else {
		if (hili_proxy_enabled == 0) {
			return 1;
		} else {
			hili_proxy_enabled = 0;
		}
	}

	return 0;
}

always_inline u32
stream_session_txrx_queue_max_dequeue (session_t *s, txrx_buffer_type_t t)
{
	FUNC_TRACE;
	u32 total_len;
	vlib_buffer_t *vb_head;
	
	vlib_main_t *vm = vlib_get_main();

	if (t == TX_BUFFER) {
		vb_head = s->send_head_b;
	} else if (t == RX_BUFFER) {
		vb_head = s->recv_head_b;
	} else {
		ft_printf("Don't support txrx buffer type\n");
		vb_head = NULL;
	}
	
	if (vb_head == NULL) {
		LINE_TRACE;
		return 0;
	}

	total_len = vlib_buffer_length_in_chain(vm, vb_head);
	//session_exchange_print("Total_len %d  in s->send_head_b chain \n", total_len);

	return total_len;
}

u32
session_bytes_in_buffer_storage(session_t *s, txrx_buffer_type_t t)
{
	FUNC_TRACE;
	u32 buff_bytes;

	if (s == NULL) {
		LINE_TRACE;
		return 0;
	}

	switch (t)
	{
		case TX_BUFFER:
			if (is_stream_session_hili_proxy_enable()) {
				buff_bytes = stream_session_txrx_queue_max_dequeue(s, t);
			} else {
				if (!s->tx_fifo)
					buff_bytes = 0;
				buff_bytes =  svm_fifo_max_dequeue (s->tx_fifo);
			}
			break;
		case RX_BUFFER:
			if (is_stream_session_hili_proxy_enable()) {
				buff_bytes = stream_session_txrx_queue_max_dequeue(s, t);
			} else {
				if (!s->rx_fifo)
					buff_bytes = 0;
				buff_bytes =  svm_fifo_max_dequeue (s->rx_fifo);
			}
			break;
		default:
			ft_printf("Unsupport txrx_buffer type\n");
			buff_bytes = 0;
	}

	return buff_bytes;
}

u32
stream_session_bytes_in_tbs_storage(transport_connection_t * tc)
{
	FUNC_TRACE;
	
	if (is_stream_session_hili_proxy_enable()) {
		LINE_TRACE;
		return hili_transport_max_tx_dequeue(tc);
	} else {
		return transport_max_tx_dequeue(tc);
		LINE_TRACE;
	}
}

int
stream_session_peek_bytes_from_tbs_storage (transport_connection_t * tc, u8 * buffer,
			   u32 offset, u32 max_bytes)
{
	FUNC_TRACE;
	
	if (is_stream_session_hili_proxy_enable()) {
		LINE_TRACE;
		return hili_session_tx_fifo_peek_bytes(tc, buffer, offset, max_bytes);
	} else {
		return session_tx_fifo_peek_bytes(tc, buffer, offset, max_bytes);
		LINE_TRACE;
	}

}

u32
stream_session_drop_bytes_from_tbs_storage(transport_connection_t * tc, u32 max_bytes)
{
	FUNC_TRACE;

	if (is_stream_session_hili_proxy_enable()) {
	   LINE_TRACE;
	   return hili_session_tx_fifo_dequeue_drop(tc, max_bytes);
	} else {
	   return session_tx_fifo_dequeue_drop(tc, max_bytes);
	   LINE_TRACE;
	}
}

u32
hili_transport_max_tx_dequeue (transport_connection_t * tc)
{
	FUNC_TRACE;
	u32 total_len;
	vlib_main_t *vm = vlib_get_main();
	session_t *s = session_get (tc->s_index, tc->thread_index);
	if (s->send_head_b == NULL) {
		LINE_TRACE;
		return 0;
	}
	total_len = vlib_buffer_length_in_chain(vm, s->send_head_b);
	//session_exchange_print("Total_len %d  in s->send_head_b chain \n", total_len);

	return total_len;
}

int
hili_session_tx_fifo_peek_bytes(transport_connection_t * tc, u8 * buffer,
			   u32 offset, u32 max_bytes)
{
	FUNC_TRACE;
	int copy_ret;
	u32 off_of_tbs;
	vlib_buffer_t *vb;
	vlib_main_t *vm = vlib_get_main();

	session_t *s = session_get (tc->s_index, tc->thread_index);
	vb = hili_session_get_tbs_buffer(s, offset, max_bytes, &off_of_tbs);

	/*The faster way is just assign the vb->data,vb->current_data, currrent_length without copy,
	 *should merge with function session_tx_fifo_chain_tail, do later; here just copy the len_to_deq
	 *byte to copy_here;
	 */
	//clib_memcpy(buffer, vb->data + vb->current_data + off_of_tbs, max_bytes);
	copy_ret = vlib_buffer_hili_copydata(vm, vb, off_of_tbs, max_bytes, buffer);
	if (copy_ret == -1) {
		LINE_TRACE;
		session_exchange_print("vlib_buffer_hili_copydata return -1 !!\n");
		session_log_debug("vlib_buffer_hili_copydata return -1 !!\n");
		return 0;
	}

	return max_bytes;
}

u32 
hili_session_tx_fifo_dequeue_drop(transport_connection_t * tc, u32 max_bytes)
{
	FUNC_TRACE;
	session_t *s = session_get (tc->s_index, tc->thread_index);
	//return svm_fifo_dequeue_drop (s->tx_fifo, max_bytes);
	return hili_session_drop_acked_holding_buffer(s, max_bytes);
}

void
hili_session_tx_fifo_dequeue_drop_all(session_t *hili_ss)
{
	vlib_main_t *vm = vlib_get_main();
	if (is_stream_session_hili_proxy_enable()) {
		if (hili_ss->send_head_b != NULL) {
			vlib_buffer_hili_free_one_buffer(vm, hili_ss->send_head_b);
		}
		hili_ss->send_head_b = hili_ss->send_tail_b = NULL;
	} else {
		svm_fifo_dequeue_drop_all (hili_ss->tx_fifo);
	}
}

#if 0
u32
session_tx_fifo_max_dequeue(transport_connection_t * tc)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  if (!s->tx_fifo)
    return 0;
  return svm_fifo_max_dequeue (s->tx_fifo);
}


int
stream_session_peek_bytes (transport_connection_t * tc, u8 * buffer,
			   u32 offset, u32 max_bytes)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_peek (s->tx_fifo, offset, max_bytes, buffer);
}


u32
stream_session_dequeue_drop (transport_connection_t * tc, u32 max_bytes)
{
  session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_dequeue_drop (s->tx_fifo, max_bytes);
}
#endif

u32
transport_max_rx_enqueue (transport_connection_t * tc)
{
	FUNC_TRACE;
	u32 max_rx_enq;
	session_t *s = session_get (tc->s_index, tc->thread_index);

	if (is_stream_session_hili_proxy_enable()) {
	   LINE_TRACE;
	   return (default_txrx_buffer_size - session_bytes_in_buffer_storage(s, RX_BUFFER));
	} else {
		LINE_TRACE;
	   return svm_fifo_max_enqueue (s->rx_fifo);
	}

}
#define LOCAL_LINE_LEN 128

static
void session_rte_hexdump(const char * title, const void * buf, unsigned int len)
{
    unsigned int i, out, ofs;
    const unsigned char *data = buf;
    char line[LOCAL_LINE_LEN];    /* space needed 8+16*3+3+16 == 75 */

    printf("%s at [%p], len=%u\n", (title)? title  : "  Dump data", data, len);
    ofs = 0;
    while (ofs < len) {
        /* format the line in the buffer, then use printf to output to screen */
        out = snprintf(line, LOCAL_LINE_LEN, "%08X:", ofs);
        for (i = 0; ((ofs + i) < len) && (i < 16); i++)
            out += snprintf(line+out, LOCAL_LINE_LEN - out, " %02X", (data[ofs+i] & 0xff));
        for(; i <= 16; i++)
            out += snprintf(line+out, LOCAL_LINE_LEN - out, " | ");
        for(i = 0; (ofs < len) && (i < 16); i++, ofs++) {
            unsigned char c = data[ofs];
            if ( (c < ' ') || (c > '~'))
                c = '.';
            out += snprintf(line+out, LOCAL_LINE_LEN - out, "%c", c);
        }
        printf("%s\n", line);
    }
}

void 
session_rte_pktmbuf_dump(vlib_main_t * vm, vlib_buffer_t *b, unsigned dump_len)
{
	unsigned int len;
	u32 chain_bi;
	vlib_buffer_t *chain_b;

	return;
	len = dump_len;
	if (len > b->current_length) {
		len = b->current_length;
	}
	if (len != 0) {
		session_rte_hexdump(NULL, vlib_buffer_get_current(b), len);
	}
	dump_len -= len;
	
	if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && dump_len > 0)) {
		chain_bi = b->next_buffer;
		do {
			chain_b = vlib_get_buffer(vm, chain_bi);
			len = dump_len;
		
			if (len > chain_b->current_length) {
				len = chain_b->current_length;
			}
		
			if (len != 0) {
				session_rte_hexdump(NULL, vlib_buffer_get_current(chain_b), len);
			}
			dump_len -= len;
			
		} while ((chain_bi = (chain_b->flags & VLIB_BUFFER_NEXT_PRESENT) ? chain_b->next_buffer : 0));
	}

}


uint32_t 
hili_session_has_data(session_t *hili_ss)
{
	FUNC_TRACE;
	uint32_t total_len;
	vlib_buffer_t *mb;
	vlib_main_t *vm = vlib_get_main();

	if (hili_ss == NULL) {
		LINE_TRACE;
		session_exchange_print("hili_ss is NULL");
		session_log_debug("hili_ss is NULL");
		return 0;
	}
	mb = hili_ss->recv_head_b;
	if (PREDICT_FALSE(mb == NULL)) {
		LINE_TRACE;
		return 0;
	}
	
	total_len = vlib_buffer_length_in_chain(vm, mb);
	/*for both pipe and tcp side session_, has_data always mean the in director*/
	session_exchange_print("The data len is %u\n",total_len);
	session_log_debug("The data len is %u\n",total_len);
	return total_len;
}

int
hili_sesssion_under_creating(session_t *hili_ss)
{
	FUNC_TRACE;

	switch (hili_ss->hili_type) {
		case SS_PIPE:   
			if (hili_ss->hili_pipe_session_state == SESSION_PIPE_STATE_CREATING) {
				session_exchange_print("Under setting consumer side\n");
				session_log_debug("Under setting consumer side\n");
				hili_ss->hili_pipe_session_state = SESSION_PIPE_STATE_EST;
				return 1;
			}
			return 0;
		case SS_TCP:
			return 0;
		default:
			session_exchange_print("unknown tle_conn hili_type %d\n", (hili_ss->hili_type));
			session_log_debug("unknown tle_conn hili_type %d\n", (hili_ss->hili_type));
			break;       
	}

	return 0;
}


/*This function now only called by pipe_input, but hili_session_current_status 
* can be use by both TCP and PIPE,so this funciton can used by TCP
*/
int
hili_session_is_reset(struct      	session_ *hili_ss)
{
	FUNC_TRACE;
    if (hili_session_current_status(hili_ss) == HILI_SESSION_CUR_BREAKUP) {
		return 1;
    }

    return 0;
}

session_cur_status_t
hili_session_current_status(struct session_ *hili_ss)
{
	FUNC_TRACE;
	vlib_main_t *vm = vlib_get_main();
    switch (hili_ss->hili_type) {
    case SS_TCP:
        {
	        if (hili_ss->hili_flags & SS_TCP_RESET || hili_ss->hili_flags & SS_TCP_APPTERM) {
				session_exchange_print("tcp type && return -1");
				session_log_debug("tcp type && return -1");
	            return HILI_SESSION_CUR_BREAKUP;
	        }
	        if ((hili_ss->hili_flags & (SS_TCP_RECV_FISRT_FIN | SS_TCP_RECV_SECOND_FIN)) && !hili_session_has_data(hili_ss)) {
				session_exchange_print("tcp type && return 1");
				session_log_debug("tcp type && return 1");
	            return HILI_SESSION_CUR_CLOSING;
	        }
			//session_exchange_print("tcp type && return 0\n");
			session_log_debug("tcp type && return 0\n");
	        return HILI_SESSION_CUR_STABLE;
        }
    case SS_PIPE:
        {
	        if (hili_ss->fwds->hili_pipe_session_state == SESSION_PIPE_STATE_TERM ||
					hili_ss->hili_pipe_session_state == SESSION_PIPE_STATE_TERM) {
				session_exchange_print("pipe type && return -1\n");
				session_log_debug("pipe type && return -1");
	            return HILI_SESSION_CUR_BREAKUP;
	        }
	        if (hili_ss->fwds->hili_pipe_session_state == SESSION_PIPE_STATE_CLOSING && !hili_session_has_data(hili_ss)) {
				session_exchange_print("pipe type && return 1");
				session_log_debug("pipe type && return 1");
	            return HILI_SESSION_CUR_CLOSING;
	        }
			//session_exchange_print("pipe type && return 0\n");
			session_log_debug("pipe type && return 0");
	        return HILI_SESSION_CUR_STABLE;
        }
    default:
        session_exchange_print("unknown hili_ss type %d\n", hili_ss->hili_type);
		session_log_debug("unknown hili_ss type %d\n", hili_ss->hili_type);
        break;
    }
    /*unreached*/
    return HILI_SESSION_CUR_STABLE;
}


always_inline int
hili_session_tcp_allowed_window(session_t *hili_ss)
{
	FUNC_TRACE;
	transport_proto_t tp;
	transport_proto_vft_t *trans_vft;
	transport_connection_t *tc;
	int32_t space;

	tc = session_get_transport(hili_ss);
	tp = session_get_transport_proto (hili_ss);
	trans_vft = transport_protocol_get_vft(tp);
	space = (int32_t) trans_vft->send_space(tc);

	session_exchange_print("Send window space : %d\n", space);
	session_log_debug("Send window space : %d", space);
	if (space <= 0) {
		hili_ss->hili_flags |= SS_TCP_APPNOWINDOW;
	}
	return space;
}

u8
hili_session_tx_not_ready(session_t * s)
{
	FUNC_TRACE;
	/* Can retransmit for closed sessions but can't send new data if
	* session is not ready or closed */

	/*This branch work for both PIPE and TCP type session*/
	if (s->session_state < SESSION_STATE_READY) {
		LINE_TRACE;
		session_exchange_print("current state is %d < SESSION_STATE_READY", s->session_state);
		session_log_debug("current state is %d < SESSION_STATE_READY", s->session_state);
		return 1;
	}
	/*This only work for TCP type session, for PIPE session keep in SESSION_STATE_READY*/
	/*CLOSING mean the app had call session_close, so should write any more*/
	if (s->session_state >= SESSION_STATE_CLOSING) {
		LINE_TRACE;
		return 2;
	}

	return 0;
}

int    
hili_session_send_window(struct       session_ *hili_ss)  
{
	FUNC_TRACE;
	switch(hili_ss->hili_type) {
		case SS_TCP:
		{
			if (hili_ss->hili_flags & SS_TCP_APPCLOSE || hili_ss->hili_flags & SS_TCP_APPTERM ||
					hili_ss->hili_flags & SS_TCP_RESET) {
				LINE_TRACE;
				session_exchange_print("hili_session_send_window tcp type return -1");
				session_log_debug("hili_session_send_window tcp type return -1");
				return -1;
			} else if (hili_session_tx_not_ready(hili_ss)) {
				LINE_TRACE;
				session_exchange_print("session_tx_not_ready not ready, return -1");
				session_log_debug("session_tx_not_ready not ready, return -1");
				return -1;
			} else {
				return hili_session_tcp_allowed_window(hili_ss);
			}
		}
		case SS_PIPE:
			return hili_session_pipe_send_window(hili_ss);
	}
    return -1;
}

int
hili_session_pipe_send_window(struct      session_ *hili_ss)
{ 
	FUNC_TRACE;
	int space_left;
    if (hili_session_current_status(hili_ss->fwds) != HILI_SESSION_CUR_STABLE) {
		LINE_TRACE;
		ft_printf("hili_session_current_status return -1\n");
        return -1;       
    }

	/*pipe session state only change to SESSION_STATE_READY from SESSION_STATE_CONNECTING*/
	if (hili_session_tx_not_ready(hili_ss)) {
		LINE_TRACE;
		ft_printf("pipe session_tx_not_ready not ready, return -1\n");
		return -1;
	}

	space_left = hili_ss->fwds->sendrightwin - hili_ss->fwds->sendenddata;
	if (space_left <= 0) {
		LINE_TRACE;
		printf("The netfe pipe buffer is full!!!!\n");
		return 0;
	}

    return space_left; 
}

int32_t
hili_session_read(vlib_main_t * vm, session_t *hili_ss, vlib_buffer_t**vb)
{
	FUNC_TRACE;

	if (vm == NULL) {
		vlib_main_t *vm = vlib_get_main();
	}

    switch (hili_ss->hili_type) {
    case SS_TCP:
        return hili_session_tcp_read(vm, hili_ss, vb);
    case SS_PIPE:
        return hili_session_pipe_read(vm, hili_ss, vb);
    default:
        printf("unknown hili_ss type %d\n", (hili_ss->hili_type));
        break;
    }

    return -1;
}

int32_t
hili_session_tcp_read(vlib_main_t * vm, struct session_ *hili_ss, vlib_buffer_t **vb)
{
	FUNC_TRACE;
	uint32_t i, n;
	uint32_t total_len;
	
	*vb = hili_ss->recv_head_b;

	if (*vb) {
		total_len = vlib_buffer_length_in_chain(vm, *vb);
		if (total_len == 0) {
			session_exchange_print("recv_head there is no data!!!!");
			session_log_debug("recv_head there is no data!!!!");
			*vb = NULL;
			return -1;
		} else {
			hili_ss->recv_head_b = NULL;
			hili_ss->recv_tail_b = NULL;
			session_exchange_print("return total_len %u", total_len);
			session_log_debug("return total_len %u", total_len);
			return total_len;
		}
	} else {
		*vb = NULL;
		session_exchange_print("n==0 and return");
		session_log_debug("n==0 and return");
		return 0;
	}

}

int32_t
hili_session_pipe_read(vlib_main_t * vm, session_t *hili_ss, vlib_buffer_t **vb)
{
	uint32_t i, n;
	uint32_t total_len;

	FUNC_TRACE;
    if (hili_session_current_status(hili_ss)  == HILI_SESSION_CUR_BREAKUP) {
		return -1;
    }

    if (hili_ss->recv_head_b == NULL) {
		if (hili_ss->fwds->hili_pipe_session_state == SESSION_PIPE_STATE_CLOSING) {
		    return -1;
		} else {
		    return 0;
		}
    }
	total_len = vlib_buffer_length_in_chain(vm, hili_ss->recv_head_b);
	
	*vb = hili_ss->recv_head_b;
	hili_ss->sendrightwin += total_len;
	hili_ss->recv_head_b = hili_ss->recv_tail_b = NULL;

	hili_session_raise_event(hili_ss->fwds, TQ_TYPE_PIPE_TOUCH_APP);
	session_exchange_print("return total_len %u", total_len);
	session_log_debug("return total_len %u", total_len);
	return total_len;

}


int32_t
hili_session_write(vlib_main_t * vm, session_t *hili_ss, vlib_buffer_t *vb, uint32_t size)
{
	FUNC_TRACE;
    switch (hili_ss->hili_type) {
    case SS_TCP:
        return hili_session_tcp_write(vm, hili_ss, vb, size);
    case SS_PIPE:
        return hili_session_pipe_write(vm, hili_ss, vb, size);
		return 0;
    default:
        printf("unknown hili_ss type %d\n", hili_ss->hili_type);
        break;
    }
    /* unreached */
    return -1;
}

/* Throw stuff into the send buffer.  Assume pkthdr mbuf. */
int32_t
hili_session_tcp_write(vlib_main_t * vm, session_t *hili_ss, vlib_buffer_t *vb,	uint32_t size)
{
	FUNC_TRACE;
	uint32_t i = 0, k = 0, n = 0;
	
	uint32_t pkt_len = vlib_buffer_length_in_chain(vm, vb);
	//hili_test_mbuf_function(m);	

	if (size > pkt_len) {
		LINE_TRACE;
		return -1;
	}

	if (size < pkt_len) {
		/*remove the needless data from the tail*/
		printf("############################Something asome happend ###############\n");
		vlib_buffer_hili_trim(vm, vb, pkt_len - size);
		pkt_len = vlib_buffer_length_in_chain(vm, vb);
		size = pkt_len;
	}

	
	if (!(hili_ss->hili_flags & SS_TCP_APPCLOSE)) {
		LINE_TRACE;
		hili_buffer_trace_print(vb);
		hili_session_tcp_chain_send_vb(vm, hili_ss, vb);
		hili_ss->hili_flags |= SS_TCP_APPWRITE;
		hili_session_raise_event(hili_ss, TQ_TYPE_TCP_CTRL_TX);
		hili_ss->sendenddata += size;
		return size;
	} else {
		return -1;
	}
}

int32_t
hili_session_pipe_write(vlib_main_t * vm, session_t *hili_ss, vlib_buffer_t *vb,	uint32_t size)
{
	uint32_t pkt_len = vlib_buffer_length_in_chain(vm, vb);
	struct session_ *peer = NULL;

	ft_printf("Enter function %s\n",__func__);
	
	if (hili_ss->hili_pipe_session_state == SESSION_PIPE_STATE_CLOSING) {
		clib_warning("Write after close");
		return -1;
	}

	if (size > pkt_len) {
		clib_warning("pipe_write called with short data");
	}

	if (size < pkt_len) {
		vlib_buffer_hili_trim(vm, vb, pkt_len - size);
		size = vlib_buffer_length_in_chain(vm, vb);
	}

	peer = hili_ss->fwds;

	hili_session_tcp_chain_recv_vb(vm, peer, vb);
	peer->sendenddata += size;

    hili_session_raise_event(peer, TQ_TYPE_PIPE_TOUCH_APP);
	return size;
}

int
hili_session_halfclose(session_t *hili_ss)
{
	FUNC_TRACE;
    switch (hili_ss->hili_type) {
    case SS_TCP:
        return hili_session_tcp_halfclose(hili_ss);
    case SS_PIPE:
        return hili_session_pipe_halfclose(hili_ss);
    default:
        printf("unknown session type %d\n", hili_ss->hili_type);
        break;
    }
    /*unreached*/
    return 1;
}

int
hili_session_tcp_halfclose(struct session_ *hili_ss)
{
	FUNC_TRACE;
    if ((hili_ss->hili_flags & SS_TCP_APPCLOSE) == 0) {
        hili_ss->hili_flags |= SS_TCP_APPCLOSE;
        hili_session_raise_event(hili_ss, TQ_TYPE_TCP_CTRL_HALF_CLOSE);
    }
    return 0;
}

int
hili_session_pipe_halfclose(struct      session_ *hili_ss)
{
	FUNC_TRACE;

	if (hili_ss->hili_pipe_session_state >= SESSION_PIPE_STATE_CLOSING) {
		return 1;
	}

	hili_ss->hili_pipe_session_state = SESSION_PIPE_STATE_CLOSING;

	hili_session_raise_event(hili_ss->fwds, TQ_TYPE_PIPE_TOUCH_APP);
	if (hili_ss->fwds->hili_pipe_session_state == SESSION_PIPE_STATE_CLOSING) {
		ft_printf("peer pipe had closed, so just schedule to delete these two netfe_streams\n");
		hili_session_raise_event(hili_ss, TQ_TYPE_PIPE_DEL);
		hili_session_raise_event(hili_ss->fwds, TQ_TYPE_PIPE_DEL);
	}
	
	return 0;
}

int
hili_session_close(session_t *hili_ss)
{
	FUNC_TRACE;
	vlib_main_t *vm = vlib_get_main();

    switch (hili_ss->hili_type) {
    case SS_TCP:
		return hili_session_tcp_close(vm, hili_ss);
	case SS_PIPE:
		return hili_session_pipe_close(vm ,hili_ss);
	default:
		printf("unknown session type %d\n", hili_ss->hili_type);
		break;
    }
    return 0;
}

int
hili_session_tcp_close(vlib_main_t *vm, session_t *hili_ss) 
{
	FUNC_TRACE;
	vlib_buffer_t *m;
	u32 bi;

	hili_session_halfclose(hili_ss);

	if (hili_session_read(vm, hili_ss, &m) > 0) {
		bi = vlib_get_buffer_index(vm, m);
		vlib_buffer_free_one(vm, bi);
	}

	m = hili_ss->reass_head_b;
	if (m) {
		bi = vlib_get_buffer_index(vm, m);
		vlib_buffer_free_one(vm, bi);
	}

	hili_ss->reass_head_b = hili_ss->reass_tail_b = NULL;
	hili_ss->rx_cb_func = NULL;

	return 0;
}

int
hili_session_pipe_close(vlib_main_t *vm, session_t *hili_ss)
{
	FUNC_TRACE;
	vlib_buffer_t *m;
	u32 bi;
	int len;

	hili_session_halfclose(hili_ss);

	len = hili_session_read(vm, hili_ss, &m);
	if (len > 0) {
		bi = vlib_get_buffer_index(vm, m);
		vlib_buffer_free_one(vm, bi);
	}
	hili_ss->rx_cb_func = NULL;

	return 0;
}

always_inline void
hili_session_tcp_free_holding_resource(session_t *hili_ss)
{
	FUNC_TRACE;
	vlib_buffer_t *m;
	u32 bi;
	vlib_main_t *vm = vlib_get_main();

	if (hili_session_read(vm, hili_ss, &m) > 0) {
		bi = vlib_get_buffer_index(vm, m);
		vlib_buffer_free_one(vm, bi);
	}

	m = hili_ss->reass_head_b;
	if (m) {
		bi = vlib_get_buffer_index(vm, m);
		vlib_buffer_free_one(vm, bi);
	}
	hili_ss->reass_head_b = hili_ss->reass_tail_b = NULL;

	m = hili_ss->send_head_b;
	if (m) {
		bi = vlib_get_buffer_index(vm, m);
		vlib_buffer_free_one(vm, bi);
	}
	hili_ss->send_head_b = hili_ss->send_tail_b = NULL;

}

always_inline void
hili_session_pipe_free_holding_resource(session_t *hili_ss)
{
	FUNC_TRACE;
	vlib_buffer_t *m;
	u32 bi;
	vlib_main_t *vm = vlib_get_main();

	if (hili_session_read(vm, hili_ss, &m) > 0) {
		bi = vlib_get_buffer_index(vm, m);
		vlib_buffer_free_one(vm, bi);
	}
}

void
hili_session_terminate(session_t *hili_ss, uint16_t rst_code)
{
	FUNC_TRACE;
    switch (hili_ss->hili_type) {
    case SS_TCP:
        hili_session_tcp_terminate(hili_ss, rst_code);
        break;
    case SS_PIPE:
        hili_ss->reset_errorcode = rst_code;
        hili_session_pipe_terminate(hili_ss);
        break;
    default:
        printf("unknown session type %d\n", hili_ss->hili_type);
        break;
    }
}

void
hili_session_tcp_terminate(struct session_ *hili_ss, uint16_t rst_code)
{
	FUNC_TRACE;
	
	if (hili_ss->hili_flags & SS_TCP_APPTERM) {
		ft_printf("tcp hili_ss had termanited!");
		return;
	}
	//hili_session_tcp_free_holding_resource(hili_ss);

	hili_ss->reset_errorcode = rst_code;
	hili_ss->hili_flags |= SS_TCP_APPTERM;
	hili_session_raise_event(hili_ss, TQ_TYPE_TCP_CTRL_TERMINATE);
}

void   
hili_session_pipe_terminate(struct      session_ *hili_ss)
{
	FUNC_TRACE;

	if (hili_ss->hili_pipe_session_state == SESSION_PIPE_STATE_TERM) {
		ft_printf("pipe hili_ss had aborted!");
		return;
	}
	
	hili_ss->hili_pipe_session_state = SESSION_PIPE_STATE_TERM;
	hili_session_pipe_free_holding_resource(hili_ss);

	if (hili_ss->fwds && !(hili_ss->fwds->hili_pipe_session_state == SESSION_PIPE_STATE_TERM)) {
		hili_session_raise_event(hili_ss->fwds, TQ_TYPE_PIPE_TOUCH_APP);
	}
	hili_session_raise_event(hili_ss, TQ_TYPE_PIPE_DEL);
}

int
hili_session_is_leaving(session_t *hili_ss)
{
	FUNC_TRACE;
    switch (hili_ss->hili_type) {
    case SS_TCP:
        {
        if (hili_ss->hili_flags & SS_TCP_RESET ||
            hili_ss->hili_flags & SS_TCP_APPTERM || 
            hili_ss->hili_flags & SS_TCP_RECV_SECOND_FIN ||
            (hili_ss->hili_flags & SS_TCP_RECV_FISRT_FIN && 
             hili_ss->hili_flags & SS_TCP_APPCLOSE)) {
            ft_printf("TCP type and return 1\n");
            return 1;
        }
		ft_printf("TCP type and return 0\n");
        return 0;
        }
    case SS_PIPE:
        {
        if (hili_ss->fwds->hili_pipe_session_state == SESSION_PIPE_STATE_TERM ||
				hili_ss->hili_pipe_session_state == SESSION_PIPE_STATE_TERM ||
					(hili_ss->fwds->hili_pipe_session_state == SESSION_PIPE_STATE_CLOSING &&
						hili_ss->hili_pipe_session_state == SESSION_PIPE_STATE_CLOSING)) {
            ft_printf("PIPE type and return 1\n");
            return 1;
        }
		ft_printf("PIPE type and return 0\n");
        return 0;
        }
    default:
        printf("unknown session type %d\n", hili_ss->hili_type);
        break;
    }

    return 0;
}

always_inline void
hili_session_pipe_fill_basic_info(session_t *hili_ss, session_t *peer_ss, session_t *tcp)
{
	FUNC_TRACE;
	hili_ss->opaque = peer_ss->opaque = tcp->opaque;
	hili_ss->sendenddata = peer_ss->sendenddata = 0;
}

session_t *             
hili_session_pipe_open(int (*rapp)(session_t *), int (*lapp)(session_t *),
	void *local_cons_side, session_t *tcp)
{
	FUNC_TRACE;
	struct session_ *hssp_local;
	struct session_ *hssp_remote;

	hssp_local = session_alloc(tcp->thread_index);
	if (hssp_local == NULL) {
		LINE_TRACE;
		return NULL;
	}

	hssp_remote = session_alloc(tcp->thread_index);
	if (hssp_remote == NULL) {
		LINE_TRACE;
		return NULL;
	}

	hili_session_set_session_state(hssp_local, SESSION_STATE_CONNECTING);
	hili_session_set_session_state(hssp_remote, SESSION_STATE_CONNECTING);
	hssp_local->hili_type |= SS_PIPE;
	hssp_remote->hili_type |= SS_PIPE;

	hssp_local->hili_pipe_session_state = SESSION_PIPE_STATE_EST;
	hssp_remote->hili_pipe_session_state = SESSION_PIPE_STATE_CREATING;

	hili_session_pipe_fill_basic_info(hssp_local, hssp_remote, tcp);

	hssp_local->fwds = hssp_remote;
	hssp_remote->fwds = hssp_local;
	hssp_local->rx_cb_func = lapp;
	hssp_remote->rx_cb_func = rapp;

	hssp_local->cons_side = local_cons_side;

	hssp_remote->rx_cb_func(hssp_remote);
	return hssp_local;
} 

uint32_t
hili_session_nread(session_t *hili_ss, vlib_buffer_t **mbuf, uint32_t num, u32 alloc_id)
{
	//SESSION_FUNC_TRACE;
	uint32_t i, k, n;
	uint32_t total_len;
	vlib_buffer_t *nb;
	vlib_main_t *vm = vlib_get_main();

	if (num == 0) {
		printf("call hili_session_nread with param num 0!!!\n");
		return 0;
	}

	if (hili_ss->recv_head_b == NULL) {
		*mbuf= NULL;
		return 0;
	}

	total_len = vlib_buffer_length_in_chain(vm, hili_ss->recv_head_b);
	session_exchange_print("Total_len before hili_session_vb_split %d", total_len);
	session_log_debug("Total_len before hili_session_vb_split %d", total_len);
	DEBUG_DUMP_SESSION_VLIB_BUFFER("hili_ss->recv_head befor hili_session_vb_split", hili_ss->recv_head_b);
	if (num >= total_len) {
		SESSION_LINE_TRACE;
		return hili_session_read(vm, hili_ss, mbuf);
	}

	*mbuf = hili_ss->recv_head_b;

	hili_ss->recv_head_b = hili_session_vb_split(vm, hili_ss->recv_head_b, num, alloc_id);

	if (!hili_ss->recv_head_b) {
		hili_ss->recv_head_b = *mbuf;
		*mbuf = NULL;
		printf("hili_ss->recv_head_d is NULL after hili_session_vb_split\n");
		return -1;
	}

	total_len = vlib_buffer_length_in_chain(vm, hili_ss->recv_head_b);
	if (total_len == 0) {
		printf("hili_session_nread pkt_len is 0 after hili_session_vb_split\n");
		vlib_buffer_hili_free_one_buffer(vm, hili_ss->recv_head_b);
		hili_ss->recv_head_b = NULL;
		*mbuf = NULL;
		return -1;
	}

	nb = hili_ss->recv_head_b;
	do {
		hili_ss->recv_tail_b = nb;
	} while (nb = vlib_get_next_buffer(vm, nb));

	session_exchange_print("Total_len left after hili_session_vb_split %d", total_len);
	session_log_debug("Total_len left after hili_session_vb_split %d", total_len);
	DEBUG_DUMP_SESSION_VLIB_BUFFER("hili_ss->recv_head after hili_session_nread", hili_ss->recv_head_b);

	return num;
}


int
hili_session_nread_silence(struct session_ *hili_ss, uint32_t off, uint32_t len, void *buf)
{
	FUNC_TRACE;
	uint32_t total_len;
	vlib_main_t *vm = vlib_get_main();

	if (hili_ss->recv_head_b == NULL) {
		LINE_TRACE;
		return -1;
	}

	total_len = vlib_buffer_length_in_chain(vm, hili_ss->recv_head_b);
	if (total_len < len) {
		LINE_TRACE;
		return -1;
	}

	return (vlib_buffer_hili_copydata(vm, hili_ss->recv_head_b, off, len, buf));
}

/*
 * Partitions an mbuf chain in two pieces.
 * Preserves the tail pointer, so that
 * it always points to the last mbuf of newly created
 * tail mbuf chain.
 * In case of failure, it returns NULL and
 * keeps input chain in its original state.
 * If last argument is non-zero, require packet header mbuf.
 * call this m_split func mean that m0 pkt_len > len0, need to split
 * used by tls state
 */
vlib_buffer_t *
hili_session_vb_split(vlib_main_t *vm, vlib_buffer_t *m0, int len0, u32 alloc_id)
{
	FUNC_TRACE;
	vlib_buffer_t *mp, *np;
	vlib_buffer_t *newmp;
	unsigned len = len0, remain;
	u32 left_total_len;
	u16 split_out_vb_cnt = 0;
	uword n_alloc;
	u32 chain_bi, remin_first_bi, newmp_next_bi;
	u32 pkt_len = vlib_buffer_length_in_chain(vm, m0);

	if (m0 == NULL) {
		LINE_TRACE;
		return NULL;
	} else if (pkt_len == 0) {
		LINE_TRACE;
		return NULL;
	}

	if (pkt_len < len0) {
		LINE_TRACE;
		return NULL;
	}

	if (len0 < 0) {
		LINE_TRACE;
		return NULL;
	}

	/* find the split point */
	for (mp = m0; mp && len > mp->current_length;) {
		len -= mp->current_length;
		mp = vlib_get_next_buffer(vm, mp);
		split_out_vb_cnt++;
	}


	if (mp == NULL) {
		LINE_TRACE;
		return NULL;
	}

	remain = mp->current_length - len;
	if (remain == 0 && !(mp->flags & VLIB_BUFFER_NEXT_PRESENT)) {
		LINE_TRACE;
		printf("remain == 0 && mp->next == NULL, the m0->pkt_len == len0, shouldn't come here\n");
		return NULL;
	}	

	/* Case 1: split point is at mbuf boundary and
	 * the next mbuf in chain is having data.
	 * break the chain at boundary.
	 * tail pointer will not change in this case.
	 */
	if (remain == 0){
		np = vlib_get_next_buffer(vm, mp); /*Here np shouldn't be NULL, becuase has check above*/
		/*mp是被读取出去的数据，因为只读了这些数据，�?以要把next 设置为NULL*/
		mp->next_buffer = 0;
		mp->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		/*mp->data_len 就是len,�?以不�?要设�?*/
		/*返回的是取出mbuf的下�?个mbuf,这样拿走了一个mbuf�? head又指向了下一个mbuf*/
		left_total_len = vlib_buffer_length_in_chain(vm, np);

		if (split_out_vb_cnt > 0) {
			m0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
			m0->flags |= VLIB_BUFFER_NEXT_PRESENT;
			m0->total_length_not_including_first_buffer = len0 - m0->current_length;
		} else {
			m0->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
			m0->flags &= ~VLIB_BUFFER_NEXT_PRESENT;		
			m0->total_length_not_including_first_buffer = 0;
		}
		session_exchange_print("return vlib buffer len is : %d", len0);
		session_log_debug("return vlib buffer len is : %d", len0);
		DEBUG_DUMP_SESSION_VLIB_BUFFER("return mbuf", m0);

		session_exchange_print("caculated left vlib buffer len is %d", left_total_len);
		session_log_debug("caculated left vlib buffer len is %d", left_total_len);
		DEBUG_DUMP_SESSION_VLIB_BUFFER("left mbuf", np);
		session_exchange_print("leave function hili_session_vb_split");
		session_log_debug("leave function hili_session_vb_split");
		return np;
	}

	/* Case 2: split point is somewhere in the mbuf
	 * allocate a new rte mbuf, then copy the data to it.
	 */
	if (remain > 0) {
		newmp_next_bi = mp->next_buffer;
		np = vlib_get_next_buffer(vm, mp);

		char *newm_startp;
		n_alloc = vlib_buffer_alloc(vm, &remin_first_bi, 1);
		if (n_alloc != 1) {
			return NULL;
		}
		newmp = vlib_get_buffer(vm, remin_first_bi);
		vlib_buffer_hili_set_alloc_module_id(newmp, alloc_id);
		/*append会把date_len设置成remain,把newmp->pkt_len 设置成remain,但是没关系下面会设置成m0->pkt_len      -len0*/
		newm_startp = (char *)vlib_buffer_put_uninit(newmp, remain);

		clib_memcpy(newm_startp, (mp->data + mp->current_data + len), remain);

		
		mp->next_buffer = 0;
		mp->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		mp->current_length = len;

		if (split_out_vb_cnt > 0) {
			m0->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
			m0->flags |= VLIB_BUFFER_NEXT_PRESENT;
			m0->total_length_not_including_first_buffer = len0 - m0->current_length;
		} else {
			m0->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
			m0->flags &= ~VLIB_BUFFER_NEXT_PRESENT;		
			m0->total_length_not_including_first_buffer = 0;
		}

		if (np) {
			newmp->next_buffer = newmp_next_bi;
			newmp->flags |= VLIB_BUFFER_NEXT_PRESENT;
		} else {
			newmp->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		}
		left_total_len = vlib_buffer_length_in_chain(vm, newmp);

		session_exchange_print("return vlib buffer len is : %d", len0);
		session_log_debug("return vlib buffer len is : %d", len0);
		DEBUG_DUMP_SESSION_VLIB_BUFFER("return mbuf", m0);

		session_exchange_print("caculated left vlib buffer len is %d", left_total_len);
		session_log_debug("caculated left vlib buffer len is %d", left_total_len);
		DEBUG_DUMP_SESSION_VLIB_BUFFER("left mbuf", newmp);
	
		session_exchange_print("leave function hili_session_vb_split\n");
		session_log_debug("leave function hili_session_vb_split\n");

		return newmp;
	}

	return NULL;
}

/*
 * Compares two mbuf chains.  Returns zero if two are equal and non-zero
 * if different.  Both mbufs have to be packet headers.
 */
int
hili_rte_pktmbuf_cmp(vlib_buffer_t *m1, vlib_buffer_t *m2)
{
	int i1, i2;
	vlib_main_t *vm = vlib_get_main();

	if (vlib_buffer_length_in_chain(vm, m1) != vlib_buffer_length_in_chain(vm, m2)) {
		return 1;
	}

	i1 = i2 = 0;

	/* skip empty mbufs at beginning */
	while (m1 && m1->current_length == 0) {
		m1 = vlib_get_next_buffer(vm, m1);
	}
	while (m2 && m2->current_length == 0) {
		m2 = vlib_get_next_buffer(vm, m2);
	}

	for (; m1;) {
		if (vlib_buffer_hili_mtod(m1, char *)[i1] != vlib_buffer_hili_mtod(m2, char *)[i2]) {
			return 1;
		}
		i1++;
		if (i1 == m1->current_length) { /* end */
			m1 = vlib_get_next_buffer(vm, m1);
			i1 = 0;
			while (m1 && m1->current_length == 0) {
				m1 = vlib_get_next_buffer(vm, m1);
			}
		}
		i2++;
		if (i2 == m2->current_length) { /* end */
			m2 = vlib_get_next_buffer(vm, m2);
			i2 = 0;
			while (m2 && m2->current_length == 0) {
				m2 = vlib_get_next_buffer(vm, m2);
			}
		}
	}

	return 0;
}

vlib_buffer_t *
hili_create_segmented_mbuf(int len, u32 alloc_module_id)
{
	FUNC_TRACE;
	u32 bi;
	vlib_main_t *vm = vlib_get_main();

	vlib_buffer_t *vb, *head_vb = NULL;

	if  (len <= MAX_PER_SEG) {
		return hili_create_one_mbuf(len, alloc_module_id);
	}

	if (1 != vlib_buffer_alloc (vm, &bi, 1)) {
		goto out_of_buffers;
	}

	head_vb = vlib_get_buffer(vm, bi);
	vlib_buffer_hili_set_alloc_module_id(head_vb, alloc_module_id);
	vlib_buffer_make_headroom(head_vb, 64);
	head_vb->current_length = MAX_PER_SEG;
	head_vb->flags |= VLIB_BUFFER_NEXT_PRESENT;
	head_vb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	head_vb->total_length_not_including_first_buffer = len - MAX_PER_SEG;

	len -= MAX_PER_SEG;
	vb = head_vb;
	while (1) {

		if (1 != vlib_buffer_alloc (vm, &vb->next_buffer, 1)) {
			goto out_of_buffers;
		}

		vb = vlib_get_buffer(vm, vb->next_buffer);
		vlib_buffer_hili_set_alloc_module_id(vb, alloc_module_id);
		vlib_buffer_make_headroom(vb, 64);
		if (len >= MAX_PER_SEG) {
			vb->current_length = MAX_PER_SEG;
		} else {
			vb->current_length = len;
		}

		len -= vb->current_length;

		if (len == 0) {
			break;
		}
		vb->flags |= VLIB_BUFFER_NEXT_PRESENT;

	}

	return head_vb;

out_of_buffers:
	clib_error ("out of buffers");
	return NULL;
}

vlib_buffer_t *
hili_create_one_mbuf(int len, u32 alloc_id)
{
	FUNC_TRACE;
	u32 bi;
	vlib_main_t *vm = vlib_get_main();
	vlib_buffer_t *vb;

	if (len > ONE_SEGMENT_MAX_LEN) {
		printf("hili_create_one_mbuf len > 1024\n");
		return NULL;
	}

	if (1 != vlib_buffer_alloc (vm, &bi, 1)) {
		goto out_of_buffers;
	}

	vb = vlib_get_buffer(vm, bi);
	//vb->opaque[9] = alloc_id;
	vlib_buffer_hili_set_alloc_module_id(vb, alloc_id);
	vlib_buffer_make_headroom(vb, 64);
	vlib_buffer_hili_init(vb);
	vb->current_length = len;
	return vb;

out_of_buffers:
	clib_error ("out of buffers");
	return NULL;

}


vlib_buffer_t *
hili_session_str2buffer(char *str, int32_t len)
{     
	FUNC_TRACE;
	vlib_buffer_t *res, *mp;
	vlib_main_t *vm = vlib_get_main();
	int more, copylen;

	if (len <= 0) {
		printf("%s len <= 0\n",__func__);
		return NULL;
	}
	
	res = hili_create_segmented_mbuf(len, 1);

	if (res == NULL) {
		ft_printf("failed to alloc vlib buffer\n");
		LINE_TRACE;
		return NULL;
	}

    more = len;

    for (mp = res; more > 0;) {
		copylen = (more > MAX_PER_SEG) ? MAX_PER_SEG : more;
		clib_memcpy(vlib_buffer_hili_mtod(mp, char *), str, copylen);
		mp->current_length = copylen;
		more -= copylen;
		str += copylen;
		mp = vlib_get_next_buffer(vm, mp);
    }

	return res;
}

vlib_buffer_t *
hili_session_get_tbs_buffer(session_t *s, u32 off, u32 len, u32 *off_of_tbs_buffer)
{
	FUNC_TRACE;
	vlib_buffer_t *next_tbs_buffer;
	vlib_buffer_t *tbs_buffer;

	vlib_main_t *vm = vlib_get_main();

	/*
	 * Is off below stored offset? Happens on retransmits.
	 * Just return, we can't help here.
	 */
	if (s->next_tbs_buffer_off > off) {
		*off_of_tbs_buffer = off;
		return s->send_head_b;
	}

	/* Return closest mbuf in chain for current offset. */
	*off_of_tbs_buffer = off - s->next_tbs_buffer_off;
	next_tbs_buffer = tbs_buffer = s->next_tbs_buffer ? s->next_tbs_buffer : s->send_head_b;
	if (*off_of_tbs_buffer == next_tbs_buffer->current_length) {
		*off_of_tbs_buffer = 0;
		s->next_tbs_buffer_off += next_tbs_buffer->current_length;
		next_tbs_buffer = tbs_buffer = vlib_get_next_buffer(vm, next_tbs_buffer);
	}

	/* Advance by len to be as close as possible for the next transmit. */
	for (off = off - s->next_tbs_buffer_off + len - 1;	 off > 0 && next_tbs_buffer != NULL && off >= next_tbs_buffer->current_length; /*next_tbs_buffer = next_tbs_buffer->m_next*/) {
		s->next_tbs_buffer_off += next_tbs_buffer->current_length;
		off -= next_tbs_buffer->current_length;
		next_tbs_buffer = vlib_get_next_buffer(vm, next_tbs_buffer);
	}

	if (off > 0 && next_tbs_buffer == NULL) {
		LINE_TRACE;
		clib_error("off > 0 and next_tbs_buffer == NULL");
	}
	s->next_tbs_buffer = next_tbs_buffer;

	return (tbs_buffer);

}

u32
hili_session_drop_acked_holding_buffer(session_t *s, u32 len)
{
	FUNC_TRACE;
	vlib_main_t *vm = vlib_get_main();
	vlib_buffer_t *vbp = s->send_head_b;
	vlib_buffer_t *prev_vbp;
	u32 next_bi;
	u32 total_len;
	u32 total_drop_len = 0;

	if (vbp == NULL) {
		LINE_TRACE;
		clib_warning("Somthing fatl error happend, send head is NULL!!!");
		return 0;
	} else {
		total_len = vlib_buffer_length_in_chain(vm, vbp);
		if (len > total_len) {
			clib_warning("Somthing fatl error happend, drop len > send head chain len !!!");
			LINE_TRACE;
			return 0;
		}
	}

	while (vbp && len > 0) {
		prev_vbp = vbp;
		if (vbp->current_length > len) {
			hili_vlib_send_buffer_advance(vbp, len);
			if (s->next_tbs_buffer_off != 0) {
				s->next_tbs_buffer_off -= len;
			}
			total_drop_len += len;
			break;
		} else {
			len -= vbp->current_length;
			if (s->next_tbs_buffer == vbp) {
				s->next_tbs_buffer = NULL;
				s->next_tbs_buffer_off = 0;
			}
			if (s->next_tbs_buffer_off != 0) {
				s->next_tbs_buffer_off -= vbp->current_length;
			}

			vbp = vlib_get_next_buffer(vm, vbp);
			prev_vbp->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
			vlib_buffer_hili_free_no_next_with_buffer(vm, prev_vbp);
		}
	}

	while (vbp && vbp->current_length == 0) {
		LINE_TRACE;
		prev_vbp = vbp;
		if (s->next_tbs_buffer == vbp) {
			s->next_tbs_buffer = vlib_get_next_buffer(vm, vbp);
		}

		vbp = vlib_get_next_buffer(vm, vbp);
		prev_vbp->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
		vlib_buffer_hili_free_no_next_with_buffer(vm, prev_vbp);
	}

	if (vbp) {
		if (PREDICT_FALSE((vbp->flags & VLIB_BUFFER_NEXT_PRESENT) == 0)) {
			vbp->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
		} else {
			vbp->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
			vlib_buffer_length_in_chain(vm, vbp);
		}
	}

	s->send_head_b = vbp;
	if (s->send_head_b == NULL) {
		s->send_tail_b = NULL;
	}
	return len;
}

int
hili_session_open_vc_tlsproxy(session_endpoint_t * rmt, u32 opaque)
{
	FUNC_TRACE;
	transport_connection_t *tc;
	transport_endpoint_t *tep;
	u32 app_index = HILI_OPEN_SESION_APP_ID;
	u64 handle;
	int rv;

	tep = session_endpoint_to_transport (rmt);
	rv = transport_connect (rmt->transport_proto, tep);
	if (rv < 0)
	{
		SESSION_DBG ("Transport failed to open connection.");
		return VNET_API_ERROR_SESSION_CONNECT;
	}

	tc = transport_get_half_open (rmt->transport_proto, (u32) rv);
	handle = (((u64) app_index) << 32) | (u64) tc->c_index;
	session_lookup_add_half_open (tc, handle);
	tc->s_index = opaque;
	ft_printf("tc->s_index %u, opaque %u\n", tc->s_index, opaque);

	return 0;
}

tlsproxy_cons_t *
tlsproxy_cons_alloc (u32 thread_index)
{
  session_worker_t *wrk = &session_main.wrk[thread_index];
  tlsproxy_cons_t *tlsc;
  u8 will_expand = 0;
  pool_get_aligned_will_expand (wrk->tlscons, will_expand,
				CLIB_CACHE_LINE_BYTES);
  /* If we have peekers, let them finish */
  if (PREDICT_FALSE (will_expand && vlib_num_workers ()))
    {
      clib_rwlock_writer_lock (&wrk->tlscons_peekers_rw_locks);
      pool_get_aligned (wrk->tlscons, tlsc, CLIB_CACHE_LINE_BYTES);
      clib_rwlock_writer_unlock (&wrk->tlscons_peekers_rw_locks);
    }
  else
    {
      pool_get_aligned (wrk->tlscons, tlsc, CLIB_CACHE_LINE_BYTES);
    }
  memset (tlsc, 0, sizeof (*tlsc));
  tlsc->tlsproxy_cons_index = tlsc - wrk->tlscons;
  tlsc->thread_index = thread_index;
  return tlsc;
}

void
tlsproxy_cons_free (tlsproxy_cons_t * tlsc)
{
  pool_put (session_main.wrk[tlsc->thread_index].tlscons, tlsc);
  if (CLIB_DEBUG)
    memset (tlsc, 0xFA, sizeof (*tlsc));
}


#endif
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

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
#include <vnet/session/application.h>
#include <vnet/session/session.h>

u8 *
format_session_fifos (u8 * s, va_list * args)
{
  session_t *ss = va_arg (*args, session_t *);
  int verbose = va_arg (*args, int);
  session_event_t _e, *e = &_e;
  u8 found;

  if (!ss->rx_fifo || !ss->tx_fifo)
    return s;

  s = format (s, " Rx fifo: %U", format_svm_fifo, ss->rx_fifo, verbose);
  if (verbose > 2 && ss->rx_fifo->has_event)
    {
      found = session_node_lookup_fifo_event (ss->rx_fifo, e);
      s = format (s, " session node event: %s\n",
		  found ? "found" : "not found");
    }
  s = format (s, " Tx fifo: %U", format_svm_fifo, ss->tx_fifo, verbose);
  if (verbose > 2 && ss->tx_fifo->has_event)
    {
      found = session_node_lookup_fifo_event (ss->tx_fifo, e);
      s = format (s, " session node event: %s\n",
		  found ? "found" : "not found");
    }
  return s;
}

/**
 * Format stream session as per the following format
 *
 * verbose:
 *   "Connection", "Rx fifo", "Tx fifo", "Session Index"
 * non-verbose:
 *   "Connection"
 */
u8 *
format_session (u8 * s, va_list * args)
{
  session_t *ss = va_arg (*args, session_t *);
  int verbose = va_arg (*args, int);
  u32 tp = session_get_transport_proto (ss);
  u8 *str = 0;

  if (ss->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
    {
      s = format (s, "[%u:%u] CLOSED", ss->thread_index, ss->session_index);
      return s;
    }

  if (verbose == 1)
    {
      u8 post_accept = ss->session_state >= SESSION_STATE_ACCEPTING;
      u8 hasf = post_accept | session_tx_is_dgram (ss);
      u32 rxf, txf;

      rxf = hasf ? svm_fifo_max_dequeue (ss->rx_fifo) : 0;
      txf = hasf ? svm_fifo_max_dequeue (ss->tx_fifo) : 0;
      str = format (0, "%-10u%-10u", rxf, txf);
    }

  if (ss->session_state >= SESSION_STATE_ACCEPTING
      || ss->session_state == SESSION_STATE_CREATED)
    {
      s = format (s, "%U", format_transport_connection, tp,
		  ss->connection_index, ss->thread_index, verbose);
      if (verbose == 1)
	s = format (s, "%v", str);
      if (verbose > 1)
	s = format (s, "%U", format_session_fifos, ss, verbose);
    }
  else if (ss->session_state == SESSION_STATE_LISTENING)
    {
      s = format (s, "%U%v", format_transport_listen_connection,
		  tp, ss->connection_index, verbose, str);
      if (verbose > 1)
	s = format (s, "\n%U", format_session_fifos, ss, verbose);
    }
  else if (ss->session_state == SESSION_STATE_CONNECTING)
    {
      s = format (s, "%-40U%v", format_transport_half_open_connection,
		  tp, ss->connection_index, str);
    }
  else
    {
      clib_warning ("Session in state: %d!", ss->session_state);
    }
  vec_free (str);

  return s;
}

uword
unformat_stream_session_id (unformat_input_t * input, va_list * args)
{
  u8 *proto = va_arg (*args, u8 *);
  u32 *fib_index = va_arg (*args, u32 *);
  ip46_address_t *lcl = va_arg (*args, ip46_address_t *);
  ip46_address_t *rmt = va_arg (*args, ip46_address_t *);
  u16 *lcl_port = va_arg (*args, u16 *);
  u16 *rmt_port = va_arg (*args, u16 *);
  u8 *is_ip4 = va_arg (*args, u8 *);
  u8 tuple_is_set = 0;
  u32 vrf = ~0;

  clib_memset (lcl, 0, sizeof (*lcl));
  clib_memset (rmt, 0, sizeof (*rmt));

  if (unformat (input, "tcp"))
    {
      *proto = TRANSPORT_PROTO_TCP;
    }
  else if (unformat (input, "udp"))
    {
      *proto = TRANSPORT_PROTO_UDP;
    }
  else
    return 0;

  if (unformat (input, "vrf %u", &vrf))
    ;

  if (unformat (input, "%U:%d->%U:%d", unformat_ip4_address, &lcl->ip4,
		lcl_port, unformat_ip4_address, &rmt->ip4, rmt_port))
    {
      *is_ip4 = 1;
      tuple_is_set = 1;
    }
  else if (unformat (input, "%U:%d->%U:%d", unformat_ip6_address, &lcl->ip6,
		     lcl_port, unformat_ip6_address, &rmt->ip6, rmt_port))
    {
      *is_ip4 = 0;
      tuple_is_set = 1;
    }

  if (vrf != ~0)
    {
      fib_protocol_t fib_proto;
      fib_proto = *is_ip4 ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6;
      *fib_index = fib_table_find (fib_proto, vrf);
    }

  return tuple_is_set;
}

uword
unformat_session (unformat_input_t * input, va_list * args)
{
  session_t **result = va_arg (*args, session_t **);
  u32 lcl_port = 0, rmt_port = 0, fib_index = 0;
  ip46_address_t lcl, rmt;
  session_t *s;
  u8 proto = ~0;
  u8 is_ip4 = 0;

  if (!unformat (input, "%U", unformat_stream_session_id, &proto, &fib_index,
		 &lcl, &rmt, &lcl_port, &rmt_port, &is_ip4))
    return 0;

  if (is_ip4)
    s = session_lookup_safe4 (fib_index, &lcl.ip4, &rmt.ip4,
			      clib_host_to_net_u16 (lcl_port),
			      clib_host_to_net_u16 (rmt_port), proto);
  else
    s = session_lookup_safe6 (fib_index, &lcl.ip6, &rmt.ip6,
			      clib_host_to_net_u16 (lcl_port),
			      clib_host_to_net_u16 (rmt_port), proto);
  if (s)
    {
      *result = s;
      session_pool_remove_peeker (s->thread_index);
      return 1;
    }
  return 0;
}

uword
unformat_transport_connection (unformat_input_t * input, va_list * args)
{
  transport_connection_t **result = va_arg (*args, transport_connection_t **);
  u32 suggested_proto = va_arg (*args, u32);
  transport_connection_t *tc;
  u8 proto = ~0;
  ip46_address_t lcl, rmt;
  u32 lcl_port = 0, rmt_port = 0, fib_index = 0;
  u8 is_ip4 = 0;

  if (!unformat (input, "%U", unformat_stream_session_id, &fib_index, &proto,
		 &lcl, &rmt, &lcl_port, &rmt_port, &is_ip4))
    return 0;

  proto = (proto == (u8) ~ 0) ? suggested_proto : proto;
  if (proto == (u8) ~ 0)
    return 0;
  if (is_ip4)
    tc = session_lookup_connection4 (fib_index, &lcl.ip4, &rmt.ip4,
				     clib_host_to_net_u16 (lcl_port),
				     clib_host_to_net_u16 (rmt_port), proto);
  else
    tc = session_lookup_connection6 (fib_index, &lcl.ip6, &rmt.ip6,
				     clib_host_to_net_u16 (lcl_port),
				     clib_host_to_net_u16 (rmt_port), proto);

  if (tc)
    {
      *result = tc;
      return 1;
    }
  return 0;
}

static clib_error_t *
show_session_command_fn (vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
  u8 one_session = 0, do_listeners = 0, sst, do_elog = 0;
  session_main_t *smm = &session_main;
  u32 transport_proto = ~0, track_index;
  session_t *pool, *s;
  transport_connection_t *tc;
  app_worker_t *app_wrk;
  int verbose = 0, i;
  int shit = 1;
  const u8 *app_name;

  if (!smm->is_enabled)
    {
      return clib_error_return (0, "session layer is not enabled");
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else if (unformat (input, "listeners %U", unformat_transport_proto,
			 &transport_proto))
	do_listeners = 1;
      else if (unformat (input, "%U", unformat_session, &s))
	{
	  one_session = 1;
	}
      else if (unformat (input, "elog"))
	do_elog = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (one_session)
    {
      u8 *str = format (0, "%U", format_session, s, 3);
      if (do_elog && s->session_state != SESSION_STATE_LISTENING)
	{
	  elog_main_t *em = &vm->elog_main;
	  f64 dt;

	  tc = session_get_transport (s);
	  track_index = transport_elog_track_index (tc);
	  dt = (em->init_time.cpu - vm->clib_time.init_cpu_time)
	    * vm->clib_time.seconds_per_clock;
	  if (track_index != ~0)
	    str = format (str, " session elog:\n%U", format_elog_track, em,
			  dt, track_index);
	}
      vlib_cli_output (vm, "%v", str);
      vec_free (str);
      return 0;
    }

  if (do_listeners)
    {
      sst = session_type_from_proto_and_ip (transport_proto, 1);
      vlib_cli_output (vm, "%-50s%-24s", "Listener", "App");
      /* *INDENT-OFF* */
      pool_foreach (s, smm->wrk[0].sessions, ({
	if (s->session_state != SESSION_STATE_LISTENING
	    || s->session_type != sst)
	  continue;
	app_wrk = app_worker_get (s->app_wrk_index);
	app_name = application_name_from_index (app_wrk->app_index);
	vlib_cli_output (vm, "%U%-25v%", format_session, s, 0,
			 app_name);
      }));
      /* *INDENT-ON* */
      return 0;
    }

  for (i = 0; i < vec_len (smm->wrk); i++)
    {
      u32 once_per_pool = 1, n_closed = 0;

      pool = smm->wrk[i].sessions;
      if (!pool_elts (pool))
	{
	  vlib_cli_output (vm, "Thread %d: no sessions", i);
	  continue;
	}

      if (!verbose)
	{
	  vlib_cli_output (vm, "Thread %d: %d sessions", i, pool_elts (pool));
	  continue;
	}

      if (once_per_pool && verbose == 1)
	{
	  vlib_cli_output (vm, "%s%-50s%-15s%-10s%-10s", i ? "\n" : "",
			   "Connection", "State", "Rx-f", "Tx-f");
	  once_per_pool = 0;
	}

      /* *INDENT-OFF* */
      pool_foreach (s, pool, ({
        if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
          {
            n_closed += 1;
			if (shit) {
				shit = 0;
				vlib_cli_output(vm, "%-10s%-10s%-10s%-10s%-44s%-10s", "state", "flags", "hili_type", "rst_id", "state transition", "reserver");
			}
			vlib_cli_output(vm, "%-10d%-10x%-10d%-10d%-4d%-4d%-4d%-4d%-4d%-4d%-4d%-4d%-4d%-4d%-4d%-10d",
				s->session_state,s->hili_flags, s->hili_type, s->reset_errorcode,
					s->ss_state_array[0], s->ss_state_array[1], s->ss_state_array[2],s->ss_state_array[3],s->ss_state_array[4],
						s->ss_state_array[5],s->ss_state_array[6],s->ss_state_array[7], s->ss_state_array[8],s->ss_state_array[9],s->ss_state_array[10], 0);
            continue;
          }
        vlib_cli_output (vm, "%U", format_session, s, verbose);
      }));
      /* *INDENT-ON* */

      if (!n_closed)
	vlib_cli_output (vm, "Thread %d: active sessions %u", i,
			 pool_elts (pool) - n_closed);
      else
	vlib_cli_output (vm, "Thread %d: active sessions %u closed %u", i,
			 pool_elts (pool) - n_closed, n_closed);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_session_command) =
{
  .path = "show session",
  .short_help = "show session [verbose [n]] [listeners <proto>] "
		"[<session-id> [elog]]",
  .function = show_session_command_fn,
};
/* *INDENT-ON* */

static int
clear_session (session_t * s)
{
  app_worker_t *server_wrk = app_worker_get (s->app_wrk_index);
  app_worker_close_notify (server_wrk, s);
  return 0;
}

static clib_error_t *
clear_session_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  session_main_t *smm = &session_main;
  u32 thread_index = 0, clear_all = 0;
  session_worker_t *wrk;
  u32 session_index = ~0;
  session_t *session;

  if (!smm->is_enabled)
    {
      return clib_error_return (0, "session layer is not enabled");
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "thread %d", &thread_index))
	;
      else if (unformat (input, "session %d", &session_index))
	;
      else if (unformat (input, "all"))
	clear_all = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!clear_all && session_index == ~0)
    return clib_error_return (0, "session <nn> required, but not set.");

  if (session_index != ~0)
    {
      session = session_get_if_valid (session_index, thread_index);
      if (!session)
	return clib_error_return (0, "no session %d on thread %d",
				  session_index, thread_index);
      clear_session (session);
    }

  if (clear_all)
    {
      /* *INDENT-OFF* */
      vec_foreach (wrk, smm->wrk)
	{
	  pool_foreach(session, wrk->sessions, ({
	    clear_session (session);
	  }));
	};
      /* *INDENT-ON* */
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (clear_session_command, static) =
{
  .path = "clear session",
  .short_help = "clear session thread <thread> session <index>",
  .function = clear_session_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_session_fifo_trace_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
  session_t *s = 0;
  u8 is_rx = 0, *str = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_session, &s))
	;
      else if (unformat (input, "rx"))
	is_rx = 1;
      else if (unformat (input, "tx"))
	is_rx = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!SVM_FIFO_TRACE)
    {
      vlib_cli_output (vm, "fifo tracing not enabled");
      return 0;
    }

  if (!s)
    {
      vlib_cli_output (vm, "could not find session");
      return 0;
    }

  str = is_rx ?
    svm_fifo_dump_trace (str, s->rx_fifo) :
    svm_fifo_dump_trace (str, s->tx_fifo);

  vlib_cli_output (vm, "%v", str);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_session_fifo_trace_command, static) =
{
  .path = "show session fifo trace",
  .short_help = "show session fifo trace <session>",
  .function = show_session_fifo_trace_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
session_replay_fifo_command_fn (vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  session_t *s = 0;
  u8 is_rx = 0, *str = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_session, &s))
	;
      else if (unformat (input, "rx"))
	is_rx = 1;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!SVM_FIFO_TRACE)
    {
      vlib_cli_output (vm, "fifo tracing not enabled");
      return 0;
    }

  if (!s)
    {
      vlib_cli_output (vm, "could not find session");
      return 0;
    }

  str = is_rx ?
    svm_fifo_replay (str, s->rx_fifo, 0, 1) :
    svm_fifo_replay (str, s->tx_fifo, 0, 1);

  vlib_cli_output (vm, "%v", str);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (session_replay_fifo_trace_command, static) =
{
  .path = "session replay fifo",
  .short_help = "session replay fifo <session>",
  .function = session_replay_fifo_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
session_enable_disable_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 is_en = 1;
  clib_error_t *error;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected enable | disable");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	is_en = 1;
      else if (unformat (line_input, "disable"))
	is_en = 0;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  unformat_free (line_input);
	  return error;
	}
    }

  unformat_free (line_input);
  return vnet_session_enable_disable (vm, is_en);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (session_enable_disable_command, static) =
{
  .path = "session",
  .short_help = "session [enable|disable]",
  .function = session_enable_disable_fn,
};
/* *INDENT-ON* */

static void
test_hili_session_set_opaque_field(vlib_buffer_t *b, u32 seq_number, u16 data_len)
{
	vnet_buffer (b)->tcp.seq_number = seq_number;
	vnet_buffer (b)->tcp.data_len = data_len;
	vnet_buffer (b)->tcp.seq_end = vnet_buffer (b)->tcp.seq_number + vnet_buffer (b)->tcp.data_len;
}

static clib_error_t *
test_hili_session_ooo_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
	vlib_buffer_t *vb, *vb1, *vb2, *vb3, *vb4, *vb5, *vb6;
	vlib_buffer_t *spec_vb;
	session_t *s;
	int first_seg_lost = 0;
	int multi_seg_lost = 0;
	int enqueue_right_overlapp = 0;
	int enqueue_left_overlapp = 0;
	int dequeue_cover_reass = 0;
	int dequeue_right_overlapp = 0;
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
	  {

		if (unformat (input, "first_seg_lost"))
			first_seg_lost = 1;
		else if (unformat (input, "enqueue_right_overlapp"))
			enqueue_right_overlapp = 1;
		else if (unformat (input, "enqueue_left_overlapp"))
			enqueue_left_overlapp = 1;
		else if (unformat (input, "dequeue_cover_reass"))
			dequeue_cover_reass = 1;
		else if (unformat (input, "dequeue_right_overlapp"))
			dequeue_right_overlapp = 1;
		else if (unformat (input, "multi_seg_lost"))
			multi_seg_lost = 1;
		else
	  return clib_error_return (0, "unknown input `%U'",
					format_unformat_error, input);
	  }


	vb1 = hili_create_one_mbuf(10, 1019);
	test_hili_session_set_opaque_field(vb1, 10, 10);

	vb2 = hili_create_one_mbuf(10, 2029);
	test_hili_session_set_opaque_field(vb2, 20, 10);

	vb3 = hili_create_one_mbuf(10, 3039);
	test_hili_session_set_opaque_field(vb3, 30, 10);

	vb4 = hili_create_one_mbuf(10, 4049);
	test_hili_session_set_opaque_field(vb4, 40, 10);

	vb5 = hili_create_one_mbuf(10, 5059);
	test_hili_session_set_opaque_field(vb5, 50, 10);

	vb6 = hili_create_one_mbuf(10, 6069);
	test_hili_session_set_opaque_field(vb6, 60, 10);

	s = session_alloc(0);
	if (first_seg_lost) {
		hili_session_enqueue_stream_connection_ooo(s, vb2);
		hili_session_enqueue_stream_connection_ooo(s, vb3);
		hili_session_enqueue_stream_connection_ooo(s, vb4);
		hili_session_enqueue_stream_connection_ooo(s, vb5);
		hili_session_enqueue_stream_connection_ooo(s, vb6);
		hili_session_enqueue_stream_try_assemble_packet(s,vb1);

		vlib_buffer_hili_free_one_buffer(vm, vb1);	/*Free vb1 and copied vb2-vb6*/
		vlib_buffer_hili_free_one_buffer(vm, vb2);	/*Free vb2*/
		vlib_buffer_hili_free_one_buffer(vm, vb3);
		vlib_buffer_hili_free_one_buffer(vm, vb4);
		vlib_buffer_hili_free_one_buffer(vm, vb5);
		vlib_buffer_hili_free_one_buffer(vm, vb6);  /*Free vb6*/
	} else if (multi_seg_lost) {
		hili_session_enqueue_stream_connection_ooo(s, vb3);
		hili_session_enqueue_stream_connection_ooo(s, vb2);
		hili_session_enqueue_stream_connection_ooo(s, vb5);
		hili_session_enqueue_stream_connection_ooo(s, vb6);
		hili_session_enqueue_stream_try_assemble_packet(s,vb1);
		vlib_buffer_hili_free_one_buffer(vm, vb1);	/*Free vb1 and copied vb2-3*/
		vlib_buffer_hili_free_one_buffer(vm, vb2);	/*Free vb2*/
		vlib_buffer_hili_free_one_buffer(vm, vb3);	/*Free vb3*/

		hili_session_enqueue_stream_try_assemble_packet(s,vb4);
		vlib_buffer_hili_free_one_buffer(vm, vb4);	/*Free vb4 and copied vb5-6*/
		vlib_buffer_hili_free_one_buffer(vm, vb5);	/*Free vb5*/
		vlib_buffer_hili_free_one_buffer(vm, vb6);	/*Free vb6*/

	} else if (enqueue_right_overlapp) {
		spec_vb = hili_create_one_mbuf(10, 2535);
		test_hili_session_set_opaque_field(spec_vb, 25, 10);

		hili_session_enqueue_stream_connection_ooo(s, vb2);
		hili_session_enqueue_stream_connection_ooo(s, vb3);
		hili_session_enqueue_stream_connection_ooo(s, spec_vb);
		hili_session_enqueue_stream_connection_ooo(s, vb4);
		hili_session_enqueue_stream_connection_ooo(s, spec_vb);
		hili_session_enqueue_stream_try_assemble_packet(s,vb1);

		vlib_buffer_hili_free_one_buffer(vm, vb1);	/*Free vb1 and copied vb2-vb4*/
		vlib_buffer_hili_free_one_buffer(vm, vb2);	/*Free vb2*/
		vlib_buffer_hili_free_one_buffer(vm, vb3);
		vlib_buffer_hili_free_one_buffer(vm, vb4);
		vlib_buffer_hili_free_one_buffer(vm, vb5);
		vlib_buffer_hili_free_one_buffer(vm, vb6);  /*Free vb6*/

		vlib_buffer_hili_free_one_buffer(vm, spec_vb);
	} else if (enqueue_left_overlapp) {
		spec_vb = hili_create_one_mbuf(5, 2227);
		test_hili_session_set_opaque_field(spec_vb, 22, 5);
	
		hili_session_enqueue_stream_connection_ooo(s, vb2);
		hili_session_enqueue_stream_connection_ooo(s, vb3);
		hili_session_enqueue_stream_connection_ooo(s, spec_vb);
		hili_session_enqueue_stream_connection_ooo(s, vb4);
		hili_session_enqueue_stream_connection_ooo(s, spec_vb);
		hili_session_enqueue_stream_try_assemble_packet(s,vb1);

		vlib_buffer_hili_free_one_buffer(vm, vb1);	/*Free vb1 and copied vb2-vb4*/
		vlib_buffer_hili_free_one_buffer(vm, vb2);	/*Free vb2*/
		vlib_buffer_hili_free_one_buffer(vm, vb3);
		vlib_buffer_hili_free_one_buffer(vm, vb4);
		vlib_buffer_hili_free_one_buffer(vm, vb5);
		vlib_buffer_hili_free_one_buffer(vm, vb6);  /*Free vb6*/

		vlib_buffer_hili_free_one_buffer(vm, spec_vb);
	} else if (dequeue_cover_reass) {
		spec_vb = hili_create_one_mbuf(20, 1029);
		test_hili_session_set_opaque_field(spec_vb, 10, 20);

		hili_session_enqueue_stream_connection_ooo(s, vb2);
		hili_session_enqueue_stream_connection_ooo(s, vb3);
		hili_session_enqueue_stream_connection_ooo(s, vb4);
		hili_session_enqueue_stream_try_assemble_packet(s, spec_vb);

		vlib_buffer_hili_free_one_buffer(vm, spec_vb);	/*Freed spec_vb and copied vb3-vb4, copied vb2 is free inner assemble*/

		vlib_buffer_hili_free_one_buffer(vm, vb1);	/*Free vb1*/
		vlib_buffer_hili_free_one_buffer(vm, vb2);	/*Free vb2*/
		vlib_buffer_hili_free_one_buffer(vm, vb3);
		vlib_buffer_hili_free_one_buffer(vm, vb4);
		vlib_buffer_hili_free_one_buffer(vm, vb5);
		vlib_buffer_hili_free_one_buffer(vm, vb6);  /*Free vb6*/

	} else if (dequeue_right_overlapp) {

		spec_vb = hili_create_one_mbuf(25, 1034);
		test_hili_session_set_opaque_field(spec_vb, 10, 25);

		hili_session_enqueue_stream_connection_ooo(s, vb2);
		hili_session_enqueue_stream_connection_ooo(s, vb3);
		hili_session_enqueue_stream_connection_ooo(s, vb4);
		hili_session_enqueue_stream_try_assemble_packet(s, spec_vb);
		vlib_buffer_hili_free_one_buffer(vm, spec_vb);	/*Free spec_vb and copied vb3-vb4, copied vb2 is free inner assemble*/

		vlib_buffer_hili_free_one_buffer(vm, vb1);	/*Free vb1*/
		vlib_buffer_hili_free_one_buffer(vm, vb2);	/*Free vb2*/
		vlib_buffer_hili_free_one_buffer(vm, vb3);
		vlib_buffer_hili_free_one_buffer(vm, vb4);
		vlib_buffer_hili_free_one_buffer(vm, vb5);
		vlib_buffer_hili_free_one_buffer(vm, vb6);  /*Free vb6*/
	} else {
		vlib_cli_output(vm, "Invalid input");
	}

	session_free(s);

}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_hili_session_ooo_command, static) =
{
  .path = "test hili session ooo",
  .short_help = "test hili session ooo [first_seg_lost] [multi_seg_lost] "
 		"[enqueue_right_overlapp] [enqueue_left_overlapp] [dequeue_cover_reass] [dequeue_right_overlapp]",
  .function = test_hili_session_ooo_fn,
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

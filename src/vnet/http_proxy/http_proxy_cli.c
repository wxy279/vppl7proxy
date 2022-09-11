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
 * HTTP proxy degug and resource checker CLI.
 *
 */

#include <vnet/http_proxy/http_proxy.h>
#include <vnet/http_proxy/http_error_def.h>

#include <vnet/tcp/tcp.h>


always_inline u8 *
format_htproxy_debug_swtich(u8 *s, va_list * args)
{
	s = format(s, "htp-resp %s	htp-req %s	htp-ups %s	htp-pipe %s	htp-conf %s		htp-ship %s",
		debug_htp_resp_statem ? "Enable" : "Disable",
		debug_htp_req_statem ? "Enable" : "Disable",
		debug_htp_ups_statem ? "Enable" : "Disable",
		debug_htp_pipe_statem ? "Enable" : "Disable",
		debug_htp_config_funcs ? "Enable" : "Disable",
		debug_htp_shipping_funcs ? "Enable" : "Disable"
			);
}

static clib_error_t *
show_htproxy_debug_command_fn(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
		vlib_cli_output(vm, "%U", format_htproxy_debug_swtich);
		return 0;

}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_htproxy_debug_command) =
{
  .path = "show htproxy debug",
  .short_help = "show htproxy debug",
  .function = show_htproxy_debug_command_fn,
};
/* *INDENT-ON* */



static clib_error_t *
htproxy_settings_enable_debug_command_fn(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "response")) {
			debug_htp_resp_statem = 1;
		} else if (unformat (input, "requst")) {
			debug_htp_req_statem = 1;
		} else if (unformat(input, "upstream")) {
			debug_htp_ups_statem = 1;
		} else if (unformat(input, "pipe")) {
			debug_htp_pipe_statem = 1;
		} else if (unformat(input, "config")) {
			debug_htp_config_funcs = 1;
		} else if (unformat(input, "shipping")) {
			debug_htp_shipping_funcs = 1;
		} else if (unformat (input, "all")) {
			debug_htp_resp_statem = debug_htp_req_statem = debug_htp_ups_statem = debug_htp_pipe_statem = debug_htp_config_funcs = debug_htp_shipping_funcs  = 1;
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}
	return 0;
}


/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_htproxy_settings_enable_debug_command) =
{
  .path = "htproxy settings enable debug",
  .short_help = "htproxy settings enable debug",
  .function = htproxy_settings_enable_debug_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
htproxy_settings_disable_debug_command_fn(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "response")) {
			debug_htp_resp_statem = 0;
		} else if (unformat (input, "requst")) {
			debug_htp_req_statem = 0;
		} else if (unformat(input, "upstream")) {
			debug_htp_ups_statem = 0;
		} else if (unformat(input, "pipe")) {
			debug_htp_pipe_statem = 0;
		} else if (unformat(input, "config")) {
			debug_htp_config_funcs = 0;
		} else if (unformat(input, "shipping")) {
			debug_htp_shipping_funcs = 0;
		} else if (unformat (input, "all")) {
			debug_htp_resp_statem = debug_htp_req_statem = debug_htp_ups_statem = debug_htp_pipe_statem = debug_htp_config_funcs = debug_htp_shipping_funcs  = 0;
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}
	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_htproxy_settings_disable_debug_command) =
{
  .path = "htproxy settings disable debug",
  .short_help = "htproxy settings disable debug",
  .function = htproxy_settings_disable_debug_command_fn,
};
/* *INDENT-ON* */

/**

 */
always_inline u8 *
format_htproxy_http_data(u8 * s, va_list * args)
{
	http_parse_data_t *http_data = va_arg (*args, http_parse_data_t *);
	int verbose = va_arg (*args, int);

	s = format(s, "%-15x%-15d%-15s%-15s", http_data->flags, http_data->rst_code,
			http_data->reqcon == NULL ? "NULL" : "Not NULL", 
				http_data->pipe == NULL ? "NULL" : "Not NULL");
	if (verbose) {
	}

	return s;
}


static clib_error_t *
show_htproxy_http_data_command_fn(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	htproxy_data_manager_main_t *htp_dmm = &htproxy_data_manager_main;
	http_parse_data_t *http_data;
	int verbose = 0;
	int i;

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {	
		if (unformat (input, "verbose %d", &verbose)) {
		} else if (unformat (input, "verbose")) {
			verbose = 1;
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}

	for (i = 0; i < vec_len(htp_dmm->http_parse_data_pools); i++) {
		u32 once_per_pool = 1;
		http_parse_data_t *pool = htp_dmm->http_parse_data_pools[i];
		if (!pool_elts(pool)) {
			vlib_cli_output(vm, "Thread %d: no http parse data", i);
		} else {
			vlib_cli_output(vm, "Thread %d: %d http parse data", i, pool_elts (pool));
		}

		if (once_per_pool && verbose == 1) {
			vlib_cli_output(vm, "%s%-15s%-15s%-15s%-15s", i ? "\n" : "",
				"HTTPFlags", "Rstcode", "TCP", "Pipe");
			once_per_pool = 0;
		}

		/* *INDENT-OFF* */
		pool_foreach (http_data, pool, ({
		  vlib_cli_output (vm, "%U", format_htproxy_http_data, http_data, verbose);
		}));
		/* *INDENT-ON* */
	}
	return 0;
	
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_htproxy_http_data_command) =
{
  .path = "show htproxy http data",
  .short_help = "show htproxy http data",
  .function = show_htproxy_http_data_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
show_htproxy_ngx_upstream_command_fn(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	htproxy_data_manager_main_t *htp_dmm = &htproxy_data_manager_main;
	//ngx_http_upstream_wrapper_t *ngx_htp_ups;
	int verbose = 0;
	int i;

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {	
		if (unformat (input, "verbose %d", &verbose)) {
		} else if (unformat (input, "verbose")) {
			verbose = 1;
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}

	for (i = 0; i < vec_len(htp_dmm->htproxy_ngx_upstream_pools); i++) {
		u32 once_per_pool = 1;
		ngx_http_upstream_wrapper_t *pool = htp_dmm->htproxy_ngx_upstream_pools[i];
		if (!pool_elts(pool)) {
			vlib_cli_output(vm, "Thread %d: no ngx upstream", i);
		} else {
			vlib_cli_output(vm, "Thread %d: %d ngx upstream", i, pool_elts (pool));
		}
	}
	return 0;
	
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_htproxy_ngx_upstream_command) =
{
  .path = "show htproxy ngx upstream",
  .short_help = "show htproxy ngx upstream",
  .function = show_htproxy_ngx_upstream_command_fn,
};
/* *INDENT-ON* */


static clib_error_t *
show_htproxy_upstream_command_fn(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	htproxy_data_manager_main_t *htp_dmm = &htproxy_data_manager_main;
	dproxy_http_upstream_t *htp_ups;
	int verbose = 0;
	int i;

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {	
		if (unformat (input, "verbose %d", &verbose)) {
		} else if (unformat (input, "verbose")) {
			verbose = 1;
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}

	for (i = 0; i < vec_len(htp_dmm->htproxy_upstream_pools); i++) {
		u32 once_per_pool = 1;
		dproxy_http_upstream_t *pool = htp_dmm->htproxy_upstream_pools[i];
		if (!pool_elts(pool)) {
			vlib_cli_output(vm, "Thread %d: no http upstream", i);
		} else {
			vlib_cli_output(vm, "Thread %d: %d http upstream", i, pool_elts (pool));
		}
	}
	return 0;
	
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_show_htproxy_upstream_command) =
{
  .path = "show htproxy upstream",
  .short_help = "show htproxy upstream",
  .function = show_htproxy_upstream_command_fn,
};
/* *INDENT-ON* */


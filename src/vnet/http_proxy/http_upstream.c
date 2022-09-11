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
 * upstream configuration.
 */

#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vnet/http_proxy/http_error_def.h>

runtime_upstream_config_tq rt_upstream_conf_tq;

http_upstream_runtime_t *
htproxy_get_upstream_rt_conf_by_name(const char *upstream_name)
{
	http_upstream_runtime_t  *rt_conf;
	TAILQ_FOREACH(rt_conf, &rt_upstream_conf_tq, next_upstream) {
		if (strcmp(rt_conf->husname, upstream_name) == 0) {
				return rt_conf;
		}
	}

	return NULL;
}

static clib_error_t *
http_upstream_add_server(vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
	char *default_client_uri = "tcp://192.168.169.136/80";
	int rv;
	u64 tmp;
	hili_lb_config_t *lbp;
	struct http_upstream_runtime_s *rt_upstream;
	htproxy_real_service_t *rs_elemt;

	hili_lb_config_enable_disable(vm, 1);
	lbp = hili_lb_config_alloc(vm->thread_index);
	u8 *client_uri;
	u8 *rs_name, *ups_name;

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	    if (unformat (input, "rs-uri %s", &client_uri)) {
			client_uri = format (0, "%s%c", client_uri, 0);
		} else if (unformat (input, "rs-name %s", &rs_name)) {
			;
		} else if (unformat (input, "ups-name %s", &ups_name)) {
	    } else {
			return clib_error_return (0, "unknown input `%U'",
						  format_unformat_error, input);
	    }
    }

	rt_upstream = htproxy_get_upstream_rt_conf_by_name(ups_name);
	if (!rt_upstream) {
		return clib_error_return (0,"Upstream %s not existed", ups_name);
	}

	if (rt_upstream->rs_num >= HTTP_UPSTREAM_RS_NUM_MAX) {
		return clib_error_return (0, "reach the limitation %d that an upstream can config rs", rt_upstream->rs_num);
	}

	if (!client_uri) {
		return clib_error_return (0, "no real server IP:PORT passed, please specific this");
	}

	rs_elemt = &rt_upstream->rs_array[rt_upstream->rs_num++];
	tp_parse_uri(client_uri, &rs_elemt->client_sep);
	rs_elemt->client_uri = client_uri;
	rs_elemt->rs_name = rs_name;
	rs_elemt->rs_type = HILI_LB_TCP_RS;

	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_htproxy_upstream_add_rs_command, static) =
{
  .path = "htproxy upstream add-rs",
  .short_help = "htproxy upstream add-rs ups-name <upstreamname> rs-name <real_server_name> [rs-uri <tcp://listen-ip/port>]"
      "[rs-uri <tcp://rs-ip/port>]",
  .function = http_upstream_add_server,
};
/* *INDENT-ON* */

static clib_error_t *
http_upstream_add_upstream(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	http_upstream_runtime_t *rt_conf;
	http_upstream_runtime_t *rt_old;

	rt_conf = clib_mem_alloc_aligned(sizeof(struct http_upstream_runtime_s), CLIB_CACHE_LINE_BYTES);
	bzero(rt_conf, sizeof(struct http_upstream_runtime_s));

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "ups-name %s", &rt_conf->husname)) {
		} else if (unformat(input, "method %s", &rt_conf->lb_method_name)) {
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}

	if (rt_old = htproxy_get_upstream_rt_conf_by_name(rt_conf->husname)) {
		clib_mem_free(rt_conf);
		return clib_error_return (0,"the server host name is existed");
	}

	if (strncmp(rt_conf->lb_method_name, "rr", strlen("rr")) == 0) {
		rt_conf->lb_method = HTTP_UPSTREAM_RR_METHOD;
	} else  if (strncmp(rt_conf->lb_method_name, "wrr", strlen("wrr")) == 0) {
		rt_conf->lb_method = HTTP_UPSTREAM_WRR_METHOD;
	} else if (strncmp(rt_conf->lb_method_name, "hi", strlen("hi")) == 0) {
		rt_conf->lb_method = HTTP_UPSTREAM_HIP_METHOD;
	} else {
		clib_mem_free(rt_conf);
		return clib_error_return (0,"Unspported load balance method");
	}
	TAILQ_INSERT_TAIL(&rt_upstream_conf_tq, rt_conf, next_upstream);

	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_htproxy_upstream_add_ups_command) =
{
  .path = "htproxy upstream add-ups",
  .short_help = "htproxy upstream add-ups ups-name <upstream_name> method <method_name>",
  .function = http_upstream_add_upstream,
};
/* *INDENT-ON* */

int htproxy_upstream_init(void)
{
	TAILQ_INIT(&rt_upstream_conf_tq);
}

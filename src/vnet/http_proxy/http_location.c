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
 * location configuration.
 */


#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vnet/http_proxy/http_error_def.h>

#define HTTP_LOCATION_NAME_MAX 64

typedef 
enum {
	HTTP_LOCATION_HLOC_OP     = 0,/*http-location*/
	HTTP_LOCATION_HURI_OP,        /*http-uri*/
	HTTP_LOCATION_HPRYP_OP,        /*proxy-pass*/
} HTTP_LOCATION_OP_e;

runtime_location_config_tq rt_location_conf_tq;

http_location_runtime_t *http_get_location_by_name(char *name)
{
	struct http_location_runtime_s *locl_cf;

	TAILQ_FOREACH(locl_cf, &rt_location_conf_tq, next_location) {
		if (strcmp(locl_cf->hlocname, name) == 0) {
				return locl_cf;
		}
	}

	return NULL;
}

static clib_error_t *
http_location_add_location(vlib_main_t * vm, unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
	char *default_client_uri = "tcp://192.168.169.136/80";
	int rv;
	u64 tmp;
	hili_lb_config_t *lbp;
	struct http_location_runtime_s *rt_location_cnf;
	struct http_location_runtime_s *rt_location_old;

	char *name;
	int len;
	rt_location_cnf = clib_mem_alloc_aligned(sizeof(struct http_location_runtime_s), CLIB_CACHE_LINE_BYTES);
	bzero(rt_location_cnf, sizeof(http_location_runtime_t));

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	    if (unformat (input, "loc-uri %s", &rt_location_cnf->loc_uri)) {
			;
		} else if (unformat (input, "loc-name %s", &rt_location_cnf->hlocname)) {
			;
	    } else {
			return clib_error_return (0, "unknown input `%U'",
						  format_unformat_error, input);
	    }
    }

	if (rt_location_old = http_get_location_by_name(rt_location_cnf->hlocname)) {
		clib_mem_free(rt_location_cnf);
		return clib_error_return (0,"the location is existed");
	}


	name = rt_location_cnf->loc_uri;
	len = strlen(name);
	if (len <= 1) {
		clib_mem_free(rt_location_cnf);
		return clib_error_return (0,"the loc-uri lengh <= 1");
	}

	if (name[0] == '=') {
		rt_location_cnf->name.len = len - 1;
		rt_location_cnf->name.data = (u_char *)name + 1;
		rt_location_cnf->exact_match = 1;
	} else if (name[0] == '^' && name[1] == '~') {
		rt_location_cnf->name.len = len - 2;
		rt_location_cnf->name.data = (u_char *)name + 2;
		rt_location_cnf->noregex = 1;
	} else if (name[0] == '~') {
		rt_location_cnf->is_regex = 1;
		if (name[1] == '*') {
			rt_location_cnf->name.len = len - 2;
			rt_location_cnf->name.data = (u_char *)name + 2;
			rt_location_cnf->caseless = 1;
#if 0
			if (my_ngx_http_core_regex_location(&rt_location_cnf->name, 1) != NGX_OK) {
				return EHTTP_INVAL;
			}
#endif
		} else {
			rt_location_cnf->name.len = len - 1;
			rt_location_cnf->name.data = (u_char *)name + 1;
			rt_location_cnf->caseless = 0;
#if 0
			if (my_ngx_http_core_regex_location(&rt_location_cnf->name, 0) != NGX_OK) {
				return EHTTP_INVAL;
			}
#endif
		}
	} else {
		rt_location_cnf->name.len = len;
		rt_location_cnf->name.data = (u_char *)name;
	}
	htp_config_debug_print("%s name.data %s, name.len %d\n", __func__, rt_location_cnf->name.data, rt_location_cnf->name.len);
	TAILQ_INSERT_TAIL(&rt_location_conf_tq, rt_location_cnf, next_location);
	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_htproxy_location_add_loc_command, static) =
{
  .path = "htproxy location add-location",
  .short_help = "htproxy location add-location loc-name <locationname> loc-uri <location uri>",
  .function = http_location_add_location,
};
/* *INDENT-ON* */

static int http_location_add_proxy_pass(vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd)
{
	http_location_runtime_t *rt_location;
	http_upstream_runtime_t *rt_upstream;
	u8 *loc_name;
	u8 *ups_name;

	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
	    if (unformat (input, "ups-name %s", &ups_name)) {
			;
		} else if (unformat (input, "loc-name %s", &loc_name)) {
			;
	    } else {
			return clib_error_return (0, "unknown input `%U'",
						  format_unformat_error, input);
	    }
    }

	rt_location = http_get_location_by_name(loc_name);
	if (rt_location == NULL) {
		return clib_error_return (0,"Location %s not existed", loc_name);
	}

	rt_upstream = htproxy_get_upstream_rt_conf_by_name(ups_name);
	if (rt_upstream == NULL) {
		return clib_error_return (0,"Upstream %s not existed", ups_name);
	}
	rt_location->rt_upstream = rt_upstream;
	return EHTTP_OK;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_htproxy_location_add_proxy_pass_command, static) =
{
  .path = "htproxy location add-proxy-pass",
  .short_help = "htproxy location add-proxy-pass loc-name <locationname> ups-name <upstream name>",
  .function = http_location_add_proxy_pass,
};
/* *INDENT-ON* */

int htproxy_location_init(void)
{
	TAILQ_INIT(&rt_location_conf_tq);
}


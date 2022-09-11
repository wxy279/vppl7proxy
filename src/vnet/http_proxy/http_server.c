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
 * virturl server configuration.
 */

#include <stdio.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bsd/sys/queue.h>

#include <string.h>
#include <vnet/http_proxy/my_ngx_http_variables.h>
#include <vnet/http_proxy/my_ngx_regex.h>
#include <vnet/http_proxy/http_error_def.h>

typedef enum {
	HTTP_SERVER_VS_OP     = 0,/*virtual server*/
	HTTP_SERVER_SN_OP,        /*server-name*/
	HTTP_SERVER_LISTEN_OP,    /*http-listen*/
	HTTP_SERVER_LOCATION_OP,  /*http-location*/
} HTTP_SERVER_OP_e;

typedef enum {
	HTTP_CONF_TYPE_SERVER = 0,
	HTTP_CONF_TYPE_UPSTREAM,
	HTTP_CONF_TYPE_LOCATION,
} HTTP_CONF_TYPE_e;

runtime_server_config_tq rt_server_conf_tq;

static ngx_int_t my_ngx_http_core_find_static_location(ngx_http_request_t *r, my_ngx_http_location_tree_node_t *node, http_location_runtime_t **location);

http_server_runtime_t *
htproxy_get_server_rt_conf_by_name(const char *hostname_arg)
{
	http_server_runtime_t  *rt_conf;

	TAILQ_FOREACH(rt_conf, &rt_server_conf_tq, next_server) {
		if (strcmp(rt_conf->hvsname, hostname_arg) == 0) {
				return rt_conf;
		}
	}

	return NULL;
}

static clib_error_t *
http_server_add_virtual_server(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	http_server_runtime_t *rt_conf;
	http_server_runtime_t *rt_old;

	rt_conf = clib_mem_alloc_aligned(sizeof(struct http_server_runtime_s), CLIB_CACHE_LINE_BYTES);
	bzero(rt_conf, sizeof(struct http_server_runtime_s));
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "vs-name %s", &rt_conf->hvsname)) {
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}

	if (rt_old = htproxy_get_server_rt_conf_by_name(rt_conf->hvsname)) {
		clib_mem_free(rt_conf);
		return clib_error_return (0,"the server host name is existed");
	}

	rt_conf->ngx_pool = ngx_create_pool(900, NULL);
	if (rt_conf->ngx_pool == NULL) {
		return NULL;
	}

	TAILQ_INSERT_TAIL(&rt_server_conf_tq, rt_conf, next_server);

	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (vlib_cli_htproxy_server_add_vs_command) =
{
  .path = "htproxy server add-vs",
  .short_help = "htproxy server add-vs vs-name <name>",
  .function = http_server_add_virtual_server,
};
/* *INDENT-ON* */

static clib_error_t * http_server_add_server_name(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	htp_config_debug_print("%s enter\n", __func__);
	char ch;
	int length;
	struct http_server_runtime_s *rt_server;

	u8	*domain_name, *vs_name;
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "server-name %s", &domain_name)) {
		} else if (unformat(input, "vs-name %s", &vs_name)) {
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}

	rt_server = htproxy_get_server_rt_conf_by_name(vs_name);

	if (!rt_server) {
		return clib_error_return (0, "Server %s not existed", vs_name);
	}

	if (rt_server->sn_number >= HTTP_SERVER_NAME_MAX) {
		htp_config_debug_print("%s virtual server %s exceed max support server names\n", __func__, rt_server->hvsname);
		return clib_error_return (0, "virtual server %s exceed max support server names", vs_name);
	}

	/*following check logic copy from ngx_http_core_server_name*/
	length = strlen(domain_name);
	if (length > HTTP_SERVER_NAME_LEN_MAX) {
		return clib_error_return (0, "Server name %s exceed max support length 64", domain_name);
	}

	ch = domain_name[0];
	if ((ch == '*' && (length < 3 || domain_name[1] != '.')) || (ch == '.' && length < 2)) {
		htp_config_debug_print("%s server name %s is invalid\n", __func__, domain_name);
		return clib_error_return (0, "server name %s is invalid", domain_name);
	}

	if (strchr(domain_name, '/')) {
		htp_config_debug_print("%s server name %s has suspicious symbols\n", __func__, domain_name);
	}

	if (ch != '~') {
		ngx_strlow((u_char *)domain_name, domain_name, length);
		snprintf(rt_server->servernames[rt_server->sn_number], HTTP_SERVER_NAME_LEN_MAX, "%s", domain_name);
	} else {
		u_char *p;
		//pcre *re;
		ngx_regex_compile_t   rc;
		//const char *errstr;
		u_char errstr[NGX_MAX_CONF_ERRSTR];
		ngx_str_t value;
		value.len = length;
		value.data = (u_char *)domain_name;

		if (length == 1) {
			return clib_error_return (0, "empty regex in server names %s", domain_name);
		}
		snprintf(rt_server->servernames[rt_server->sn_number], HTTP_SERVER_NAME_LEN_MAX, "%s", domain_name);
		value.len--;
		value.data++;
		ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

		rc.pattern = value;
		rc.err.len = NGX_MAX_CONF_ERRSTR;
		rc.err.data = errstr;

		for (p = value.data; p < value.data + value.len; p++) {
			if (*p >= 'A' && *p <= 'Z') {
				rc.options = NGX_REGEX_CASELESS;
				break;
			}
		}

		rt_server->regex[rt_server->sn_regex_number] = my_ngx_http_regex_compile(rt_server->ngx_pool, &rc);
		if (rt_server->regex[rt_server->sn_regex_number] == NULL) {
			htp_config_debug_print("%s my_ngx_http_regex_compile compilation failed  %s server names %s\n", __func__, errstr, domain_name);

			return clib_error_return (0, "my_ngx_http_regex_compile compilation failed  %s server names %s", errstr, domain_name);
		}
		rt_server->sn_regex_number++;
	}

	rt_server->sn_number++;
	return EHTTP_OK;
}


/* *INDENT-OFF* */

VLIB_CLI_COMMAND (vlib_cli_htproxy_server_add_sn_command) =
{
  .path = "htproxy server add-sn",
  .short_help = "htproxy server add-sn server-name <domainname> vs-name <vsname>",
  .function = http_server_add_server_name,
};
/* *INDENT-ON* */

static ngx_int_t my_ngx_http_core_regex_location(http_server_runtime_t *server, http_location_runtime_t *location, ngx_str_t *regex, ngx_uint_t caseless)
{
	ngx_regex_compile_t  rc;
	u_char               errstr[NGX_MAX_CONF_ERRSTR];

	ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

	rc.pattern = *regex;
	rc.err.len = NGX_MAX_CONF_ERRSTR;
	rc.err.data = errstr;

	rc.options = caseless ? NGX_REGEX_CASELESS : 0;

	location->regex = my_ngx_http_regex_compile(server->ngx_pool, &rc);
	if (location->regex == NULL) {
		return NGX_ERROR;
	}

	//clcf->name = *regex;

	return NGX_OK;

}

static clib_error_t * http_server_add_location(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	char ch;
	int length;
	struct http_server_runtime_s *rt_server;
	struct http_location_runtime_s *location;
	my_ngx_http_location_queue_t  *lq;
	ngx_uint_t caseless;

	u8	*loc_name, *vs_name;
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "loc-name %s", &loc_name)) {
		} else if (unformat(input, "vs-name %s", &vs_name)) {
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}

	rt_server = htproxy_get_server_rt_conf_by_name(vs_name);

	if (!rt_server) {
		return clib_error_return (0, "Server %s not existed", vs_name);
	}

	location = http_get_location_by_name(loc_name);

	if (location == NULL) {
		return clib_error_return (0, "Location %s not existed", loc_name);
	}

	if (rt_server->locations == NULL) {
		rt_server->locations = ngx_palloc(rt_server->ngx_pool, sizeof(my_ngx_http_location_queue_t));
		if (rt_server->locations == NULL) {
			return clib_error_return (0, "Failed to alloc memory for location queues for server %s", vs_name);
		}
		ngx_queue_init(rt_server->locations);
	}

	if (location->is_regex) {
		if (rt_server->regex_loc_nb >= HTTP_SERVER_REGEX_LOCATION_MAX) {
			return clib_error_return (0,"reach the limitation of max regex of a server");
		}
		caseless = location->caseless;
		if (my_ngx_http_core_regex_location(rt_server, location, &location->name, caseless) != NGX_OK) {
			return clib_error_return (0,"my_ngx_http_core_regex_location failed");
		}
		rt_server->regex_locations[rt_server->regex_loc_nb++] = location;
	} else {
		lq = ngx_palloc(rt_server->ngx_pool, sizeof(my_ngx_http_location_queue_t));
		if (lq == NULL) {
			return clib_error_return (0,"Failed to alloc location queue structure");
		}

		if (location->exact_match/*|| location->regex  TODO */) {
			lq->exact = location;
			lq->inclusive = NULL;
		} else {
			lq->exact = NULL;
			lq->inclusive = location;
		}

		lq->name = &location->name;

		ngx_queue_init(&lq->list);
		ngx_queue_insert_tail(rt_server->locations, &lq->queue);
	}
	return EHTTP_OK;
}


/* *INDENT-OFF* */

VLIB_CLI_COMMAND (vlib_cli_htproxy_server_add_loc_command) =
{
  .path = "htproxy server add-location",
  .short_help = "htproxy server add-location loc-name <locationname> vs-name <vsname>",
  .function = http_server_add_location,
};
/* *INDENT-ON* */

static ngx_int_t ngx_http_cmp_locations(const ngx_queue_t *one, const ngx_queue_t *two)
{
	ngx_int_t                   rc;
	struct http_location_runtime_s   *first, *second;
	my_ngx_http_location_queue_t  *lq1, *lq2;

	lq1 = (my_ngx_http_location_queue_t *) one;
	lq2 = (my_ngx_http_location_queue_t *) two;

	first = lq1->exact ? lq1->exact : lq1->inclusive;
	second = lq2->exact ? lq2->exact : lq2->inclusive;

#if 0
    if (first->regex && !second->regex) {
        /* shift the regex matches to the end */
        return 1;
    }

    if (!first->regex && second->regex) {
        /* shift the regex matches to the end */
        return -1;
    }

    if (first->regex || second->regex) {
        /* do not sort the regex matches */
        return 0;
    }
#endif

	rc = ngx_filename_cmp(first->name.data, second->name.data,
						  ngx_min(first->name.len, second->name.len) + 1);

	if (rc == 0 && !first->exact_match && second->exact_match) {
		/* an exact match must be before the same inclusive one */
		return 1;
	}

	return rc;
}

static ngx_int_t my_ngx_http_init_locations(http_server_runtime_t *server)
{
#if 0
	ngx_uint_t                   n;
	ngx_queue_t                 *q, *locations, *named, tail;
#endif
	ngx_queue_t *locations;
	locations = server->locations;
	if (locations == NULL) {
		return NGX_ERROR;
	}

	ngx_queue_sort(locations, ngx_http_cmp_locations);
	return NGX_OK;
}

static ngx_int_t my_ngx_http_join_exact_locations(ngx_queue_t *locations)
{
	ngx_queue_t                *q, *x;
	my_ngx_http_location_queue_t  *lq, *lx;
	q = ngx_queue_head(locations);

	while (q != ngx_queue_last(locations)) {

		x = ngx_queue_next(q);

		lq = (my_ngx_http_location_queue_t *)q;
		lx = (my_ngx_http_location_queue_t *)x;

		if (lq->name->len == lx->name->len &&
			ngx_filename_cmp(lq->name->data, lx->name->data, lx->name->len) == 0) {
			if ((lq->exact && lx->exact) || (lq->inclusive && lx->inclusive)) {
				//(ERR, HTTP_SERVER, "%s duplicate location %s\n", __func__, lq->name->data);
				return NGX_ERROR;
			}

			lq->inclusive = lx->inclusive;
			ngx_queue_remove(x);

			continue;
		}

		q = ngx_queue_next(q);
	}

	return NGX_OK;
}



static void my_ngx_http_create_locations_list(ngx_queue_t *locations, ngx_queue_t *q)
{
    u_char                     *name;
    size_t                      len;
    ngx_queue_t                *x, tail;
    my_ngx_http_location_queue_t  *lq, *lx;

    if (q == ngx_queue_last(locations)) {
        return;
    }

    lq = (my_ngx_http_location_queue_t *) q;

    if (lq->inclusive == NULL) {
        my_ngx_http_create_locations_list(locations, ngx_queue_next(q));
        return;
    }

    len = lq->name->len;
    name = lq->name->data;

    for (x = ngx_queue_next(q);
         x != ngx_queue_sentinel(locations);
         x = ngx_queue_next(x))
    {
        lx = (my_ngx_http_location_queue_t *) x;

        if (len > lx->name->len
            || ngx_filename_cmp(name, lx->name->data, len) != 0)
        {
            break;
        }
    }

    q = ngx_queue_next(q);

    if (q == x) {
        my_ngx_http_create_locations_list(locations, x);
        return;
    }

    ngx_queue_split(locations, q, &tail);
    ngx_queue_add(&lq->list, &tail);

    if (x == ngx_queue_sentinel(locations)) {
        my_ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));
        return;
    }

    ngx_queue_split(&lq->list, x, &tail);
    ngx_queue_add(locations, &tail);

    my_ngx_http_create_locations_list(&lq->list, ngx_queue_head(&lq->list));

    my_ngx_http_create_locations_list(locations, x);
}

static my_ngx_http_location_tree_node_t *
my_ngx_http_create_locations_tree(http_server_runtime_t *server, ngx_queue_t *locations, size_t prefix)
{
	size_t                          len;
	ngx_queue_t                    *q, tail;
	my_ngx_http_location_queue_t      *lq;
	my_ngx_http_location_tree_node_t  *node;

	q = ngx_queue_middle(locations);

	lq = (my_ngx_http_location_queue_t *) q;
	len = lq->name->len - prefix;

	node = ngx_palloc(server->ngx_pool, offsetof(my_ngx_http_location_tree_node_t, name) + len);
	if (node == NULL) {
		return NULL;
	}

	node->left = NULL;
	node->right = NULL;
	node->tree = NULL;
	node->exact = lq->exact;
	node->inclusive = lq->inclusive;
	node->auto_redirect = 0;

	node->len = (u_char) len;
	ngx_memcpy(node->name, &lq->name->data[prefix], len);
	//(ERR, HTTP_SERVER, "%s node name %s and len is %d\n", __func__,node->name, len);
	ngx_queue_split(locations, q, &tail);
	if (ngx_queue_empty(locations)) {
		goto inclusive;
	}

	node->left = my_ngx_http_create_locations_tree(server, locations, prefix);

	if (node->left == NULL) {
		return NULL;
	}

	ngx_queue_remove(q);

	if (ngx_queue_empty(&tail)) {
		goto inclusive;
	}

	node->right = my_ngx_http_create_locations_tree(server, &tail, prefix);
	if (node->right == NULL) {
		return NULL;
	}

inclusive:

	if (ngx_queue_empty(&lq->list)) {
		return node;
	}

	node->tree = my_ngx_http_create_locations_tree(server, &lq->list, prefix + len);
	if (node->tree == NULL) {
		return NULL;
	}

	return node;
}

static ngx_int_t my_http_init_static_location_trees(http_server_runtime_t *server)
{
	ngx_queue_t                *locations;
	//my_ngx_http_location_queue_t  *lq;

	locations = server->locations;
	if (locations == NULL) {
		return NGX_ERROR;
	}
	if (ngx_queue_empty(locations)) {
		return NGX_OK;
	}
	/*don't support nested location, so no nessary to do folowing loop*/
#if 0
	for (q = ngx_queue_head(locations); q != ngx_queue_sentinel(locations); q = ngx_queue_next(q)) {
		lq = (my_ngx_http_location_queue_t *)q;
		rt_loc = lq->exact ? lq->exact : lq->inclusive;
	}
#endif

	if (my_ngx_http_join_exact_locations(locations) != NGX_OK) {
		return NGX_ERROR;
	}

	my_ngx_http_create_locations_list(locations, ngx_queue_head(locations));

	server->static_locations = my_ngx_http_create_locations_tree(server, locations, 0);
	if (server->static_locations == NULL) {
		return NGX_ERROR;
	}
	return NGX_OK;
}

static void http_server_find_location_test(http_server_runtime_t *server)
{
	int i;
	ngx_int_t n;
	ngx_http_request_t r;
	http_location_runtime_t *location = NULL;
	ngx_str_t test_uri = ngx_string("/static/");
	memset(&r, 0x0, sizeof(ngx_http_request_t));
	r.uri.len = test_uri.len;
	r.uri.data = test_uri.data;

	my_ngx_http_core_find_static_location(&r, server->static_locations, &location);
	if (location != NULL) {
		htp_config_debug_print("%s find location %s and uri is %s\n", __func__, location->hlocname, location->name.data);
	} else {
		htp_config_debug_print("%s my_ngx_http_core_find_static_location find nothing!\n", __func__);
	}
	if (server->regex_loc_nb > 0) {
		ngx_str_t test_reg_uri = ngx_string("/static.jpg");
		r.uri.len = test_reg_uri.len;
		r.uri.data = test_reg_uri.data;
		for (i = 0; i < server->regex_loc_nb; i++) {
			location = server->regex_locations[i];
			n = my_ngx_http_regex_exec_conf(server->ngx_pool, &r, location->regex, &r.uri);
			if (n == NGX_OK) {
				htp_config_debug_print("%s find location %s and uri is %s\n", __func__, location->hlocname, location->name.data);
				break;
			}
		}
		if (i == server->regex_loc_nb) {
			htp_config_debug_print("%s regex_loc_nb not 0 but find nothing!\n", __func__);
		}
	} else {
		htp_config_debug_print("%s server->regex_loc_nb == 0\n", __func__);
	}
}

static clib_error_t * http_server_add_listen(vlib_main_t * vm, unformat_input_t * input,
			 vlib_cli_command_t * cmd)
{
	htp_config_debug_print("Enter func %s\n", __func__);
	char ch;
	int length;
	struct http_server_runtime_s *rt_server;
	hili_lb_config_t	 *lbcp;
	http_server_match_t *lbmatch_s;
	struct http_server_runtime_s *find_server;

	u8	*lb_name, *vs_name;
	while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT) {
		if (unformat (input, "lb-name %s", &lb_name)) {
		} else if (unformat(input, "vs-name %s", &vs_name)) {
		} else {
			return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
		}
	}

	rt_server = htproxy_get_server_rt_conf_by_name(vs_name);

	if (!rt_server) {
		return clib_error_return (0,"virtual server %s not exist", vs_name);
	}

	if ((lbcp = hili_get_lb_config_by_name(lb_name)) == NULL) {
		return clib_error_return (0,"lb %s not existed", lb_name);
	}

	if (ngx_queue_empty(rt_server->locations)) {
		return clib_error_return (0,"No location configured on server %s", vs_name);
	}

	if (rt_server->sn_number == 0) {
		return clib_error_return (0,"No domain name configed on server %s", vs_name);
	}

	lbcp->app_config = clib_mem_alloc_aligned(sizeof(struct http_server_match_s), CLIB_CACHE_LINE_BYTES);
	if (lbcp->app_config == NULL) {
		return clib_error_return (0,"Failed to get http server match structure");
	}
	memset (lbcp->app_config, 0x0, sizeof (http_server_match_t));
	lbmatch_s = (http_server_match_t *)lbcp->app_config;

	if (lbmatch_s->virtual_names == NULL) {
		//vs->virtual_names = rte_zmalloc("ngx_http_virtual_names", size, RTE_CACHE_LINE_SIZE);
		lbmatch_s->virtual_names = clib_mem_alloc_aligned(sizeof(ngx_http_virtual_names_t), CLIB_CACHE_LINE_BYTES);
		if (lbmatch_s->virtual_names == NULL) {
			return clib_error_return (0,"Failed to get ngx_http_virtual_names_t structure");
		}
	}

	/*ngx_http_optimize_servers logic start*/
	if (my_ngx_http_init_locations(rt_server) != NGX_OK) {
		return clib_error_return (0, "%s my_ngx_http_init_locations failed\n", __func__);
	}

	if (my_http_init_static_location_trees(rt_server) != NGX_OK) {
		return clib_error_return (0, "%s my_ngx_http_init_locations failed\n", __func__);
	}

#if 1
	/*test location static tree lookup*/
	http_server_find_location_test(rt_server);
#endif

	/*ngx_http_optimize_servers logic start*/
	{
		int i;
		int regex = 0;
		ngx_int_t rc;
		ngx_pool_t *pool1, *pool2;
		ngx_hash_init_t hash_init;
		ngx_hash_keys_arrays_t hash_array;
		ngx_hash_combined_t *combinedHash = &lbmatch_s->virtual_names->names;
		pool1 = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, NULL);
		if (pool1 == NULL) {
			return clib_error_return (0, "%s ngx_create_pool failed\n", __func__);
		}
		pool2 = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, NULL);
		if (pool2 == NULL) {
			return clib_error_return (0, "%s ngx_create_pool failed\n", __func__);
		}

		ngx_cacheline_size = NGX_CPU_CACHE_LINE;
		
		hash_array.pool = pool1;
		hash_array.temp_pool = pool2;

		if (ngx_hash_keys_array_init(&hash_array, NGX_HASH_SMALL) != NGX_OK) {
			return clib_error_return (0, "%s ngx_hash_keys_array_init failed\n", __func__);
		}

		ngx_str_t add_kv;
		add_kv.data = ngx_palloc(pool1, HTTP_SERVER_NAME_LEN_MAX);
		for (i = 0; i < rt_server->sn_number; i++) {
			if (rt_server->regex[i]) {
				regex++;
				continue;
			}
			add_kv.len = strlen(rt_server->servernames[i]);
			memcpy(add_kv.data, rt_server->servernames[i], add_kv.len);
			rc = ngx_hash_add_key(&hash_array, &add_kv, rt_server, NGX_HASH_WILDCARD_KEY);
			if (rc == NGX_ERROR) {
				return clib_error_return (0, "%s ngx_hash_add_key failed\n", __func__);
			}
		}

		hash_init.key = ngx_hash_key_lc;
		hash_init.max_size = 128;
		hash_init.bucket_size = 64;
		hash_init.name = "hash_array_name";
		hash_init.pool = pool1;

		if (hash_array.keys.nelts) {
			hash_init.hash = &combinedHash->hash;
			hash_init.temp_pool = NULL;
			if (ngx_hash_init(&hash_init, hash_array.keys.elts, hash_array.keys.nelts) != NGX_OK) {
				return clib_error_return (0, "%s ngx_hash_init failed\n", __func__);
			}
		}

		if(hash_array.dns_wc_head.nelts){
			hash_init.hash = NULL;
			hash_init.temp_pool = hash_array.temp_pool;
			if (ngx_hash_wildcard_init(&hash_init, hash_array.dns_wc_head.elts, hash_array.dns_wc_head.nelts) != NGX_OK) {
				return clib_error_return (0, "%s ngx_hash_wildcard_init failed\n", __func__);
			}
			combinedHash->wc_head = (ngx_hash_wildcard_t *)hash_init.hash;
		}

		if(hash_array.dns_wc_tail.nelts){
			hash_init.hash = NULL;
			hash_init.temp_pool = hash_array.temp_pool;
			if (ngx_hash_wildcard_init(&hash_init, hash_array.dns_wc_tail.elts, hash_array.dns_wc_tail.nelts) != NGX_OK) {
				return clib_error_return (0, "%s ngx_hash_wildcard_init failed\n", __func__);
			}
			combinedHash->wc_tail = (ngx_hash_wildcard_t *)hash_init.hash;
		}

		ngx_uint_t h;
		//查找利用通配符查�?
#if 1
		ngx_str_t k6;
		k6.len = strlen(rt_server->servernames[0]);
		k6.data = (u_char *)rt_server->servernames[0];
		//memcpy(k6.data, exist_cnf->servernames[0], strlen(exist_cnf->servernames[0]));
#endif
		h = ngx_hash_key_lc((u_char *)k6.data, k6.len);
#if 1
		find_server = ngx_hash_find_combined(combinedHash, h, (u_char *)k6.data, k6.len);
#else
		find_server = ngx_hash_find_combined(&combinedHash, h, exist_cnf->servernames[0], strlen(exist_cnf->servernames[0]));
#endif

		if (find_server == NULL) {
			clib_error_return (0, "%s ngx_hash_find_combined find nothing\n", __func__);
		}else{
			clib_error_return (0, "%s ngx_hash_wildcard_init find a server, first configed server name %s\n", __func__, find_server->servernames[0]);
		}

		if (regex) {
			/*The dp vs service only can config DP_VS_SERVICE_MAX_REGEX_SERVER regex host, TODO should use ngx array*/
			if (lbmatch_s->regex_server_nb + regex > DP_VS_SERVICE_MAX_REGEX_SERVER) {
				return clib_error_return (0, "%s dpvs service left item number less then %d\n", __func__, regex);
			}
			int i;
			http_server_regex_map_t *server_regexs = lbmatch_s->regex_servers;
			for (i = 0; i < regex; i++) {
				server_regexs[lbmatch_s->regex_server_nb].regex = rt_server->regex[i];
				server_regexs[lbmatch_s->regex_server_nb].server = rt_server;
				lbmatch_s->regex_server_nb++;
			}
		}
	}
	return 0;
}

/* *INDENT-OFF* */

VLIB_CLI_COMMAND (vlib_cli_htproxy_server_attach_lb_command) =
{
  .path = "htproxy server attach-lb",
  .short_help = "htproxy server attach-lb lb-name <lbname> vs-name <vsname>",
  .function = http_server_add_listen,
};
/* *INDENT-ON* */


/*
 * NGX_OK       - exact match
 * NGX_DONE     - auto redirect
 * NGX_AGAIN    - inclusive match
 * NGX_DECLINED - no match
 */
#define DPROXY_RUN_FRAMEWORK 1

static ngx_int_t my_ngx_http_core_find_static_location(ngx_http_request_t *r, my_ngx_http_location_tree_node_t *node, http_location_runtime_t **location)
{
	u_char	   *uri;
	size_t		len, n;
	ngx_int_t	rc, rv;

#ifdef DPROXY_RUN_FRAMEWORK
	/*should refer ngx_http_process_request_uri to handle uri correctly*/
	r->uri.len = r->uri_end - r->uri_start;
	r->uri.data = r->uri_start;
#endif

	len = r->uri.len;
	uri = r->uri.data;

	rv = NGX_DECLINED;

	for ( ;; ) {

		if (node == NULL) {
			return rv;
		}

		//(ERR, HTTP_SERVER, "%s test location: %s\n", __func__, node->name);


		n = (len <= (size_t) node->len) ? len : node->len;

		rc = ngx_filename_cmp(uri, node->name, n);

		if (rc != 0) {
			node = (rc < 0) ? node->left : node->right;

			continue;
		}

		if (len > (size_t) node->len) {

			if (node->inclusive) {
				*location = node->inclusive;
				//r->loc_conf = node->inclusive->loc_conf;
				rv = NGX_AGAIN;

				node = node->tree;
				uri += n;
				len -= n;

				continue;
			}

			/* exact only */

			node = node->right;

			continue;
		}

		if (len == (size_t) node->len) {
			if (node->exact) {
				//r->loc_conf = node->exact->loc_conf;
				*location = node->exact;
				return NGX_OK;
			} else {
				//r->loc_conf = node->inclusive->loc_conf;
				*location = node->inclusive;
				return NGX_AGAIN;
			}
		}

		/* len < node->len */
#if 0
		if (len + 1 == (size_t) node->len && node->auto_redirect) {/*Caogw current auto_redirect is 0 by default*/

			r->loc_conf = (node->exact) ? node->exact->loc_conf:
										  node->inclusive->loc_conf;
			rv = NGX_DONE;
		}
#endif
		node = node->left;
	}
}


ngx_int_t my_ngx_http_core_find_location(ngx_http_request_t *r, http_server_runtime_t *server, http_location_runtime_t **location)
{
		ngx_int_t rc;
		ngx_int_t n;
		int i;
		http_location_runtime_t *regx_location = NULL;
		rc = my_ngx_http_core_find_static_location(r, server->static_locations, location);

		if (rc == NGX_OK || rc == NGX_DONE) {
			return rc;
		}

		/* rc == NGX_DECLINED or rc == NGX_AGAIN in nested location */

#if 1
		if (server->regex_loc_nb > 0) {
			for (i = 0; i < server->regex_loc_nb; i++) {
				regx_location = server->regex_locations[i];
				n = my_ngx_http_regex_exec(r, regx_location->regex, &r->uri);
				if (n == NGX_OK) {
					*location = regx_location;
					htp_req_debug_print("%s find location %s and uri is %s\n", __func__, regx_location->hlocname, regx_location->name.data);
					return NGX_OK;
				}
				if (n == NGX_DECLINED) {
					continue;
				}
				return NGX_ERROR;
			}
			if (i == server->regex_loc_nb) {
				htp_req_debug_print("%s regex_loc_nb not 0 but find nothing!\n", __func__);
			}
		}
#endif

	return rc;

}

ngx_int_t myngx_http_process_host(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset, struct http_parse_data_s *http_data)
{
	int i;
	ngx_int_t n;
	struct http_server_runtime_s *find_server;
	hili_lb_config_t *lb_conf = http_data->lb_conf;

	http_server_match_t *lbmatch_s = lb_conf->app_config;
	
	http_server_regex_map_t *regex_servers = lbmatch_s->regex_servers;

	ngx_hash_combined_t *combinedHash = &lbmatch_s->virtual_names->names;
	ngx_str_t host;

	if (r->headers_in.host == NULL) {
		r->headers_in.host = h;
	}
	host = h->value;
	find_server = ngx_hash_find_combined(combinedHash, ngx_hash_key(host.data, host.len), host.data, host.len);

	if (find_server == NULL) {
		htp_req_debug_print("%s ngx_hash_find_combined find nothing\n", __func__);
		//return NGX_ERROR; should continue to lookup by regex
	} else {
		http_data->http_server = find_server;
		htp_req_debug_print("%s ngx_hash_wildcard_init find a server, first configed server name %s\n", __func__, find_server->servernames[0]);
	}

	if (lbmatch_s->regex_server_nb > 0) {
		for (i = 0; i < lbmatch_s->regex_server_nb; i++) {
			n = my_ngx_http_regex_exec(r, regex_servers[i].regex, &host);

			if (n == NGX_DECLINED) {
				continue;
			}

			if (n == NGX_OK) {
				http_data->http_server = regex_servers[i].server;
				htp_req_debug_print("%s my_ngx_http_regex_exec find a server, first configed server name %s\n", __func__, http_data->http_server->servernames[0]);
				return NGX_OK;
			}
			return NGX_ERROR;
		}
	}
	return NGX_OK;
}

int htproxy_server_init(void)
{
	my_ngx_regex_init();
	//ngx_http_headers_in[0].handler  = myngx_http_process_host;
	TAILQ_INIT(&rt_server_conf_tq);
	return 1;
}


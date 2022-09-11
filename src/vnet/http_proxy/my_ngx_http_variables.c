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

#include <vnet/http_proxy/my_ngx_http_variables.h>
#include <vnet/http_proxy/my_ngx_regex.h>

ngx_http_regex_t *my_ngx_http_regex_compile(my_ngx_pool_t *pool, ngx_regex_compile_t *rc)
{
#if 1
#if 0
	u_char					   *p;
	size_t						size;
	ngx_str_t					name;
#endif

	ngx_uint_t					n;
	ngx_http_regex_t		   *re;

	//rc->pool = cf->pool;

	if (my_ngx_regex_compile(pool, rc) != NGX_OK) {
		//ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc->err);
		return NULL;
	}

	//re = my_ngx_pcalloc(pool, sizeof(ngx_http_regex_t));
	re = ngx_pcalloc(pool, sizeof(ngx_http_regex_t));
	if (re == NULL) {
		return NULL;
	}

	re->regex = rc->regex;
	re->ncaptures = rc->captures;
	re->name = rc->pattern;

	n = (ngx_uint_t) rc->named_captures;

	if (n == 0) {
		return re;
	}
	re->nvariables = n;

#if 0
	rv = ngx_palloc(rc->pool, n * sizeof(ngx_http_regex_variable_t));
	if (rv == NULL) {
		return NULL;
	}

	re->variables = rv;
	re->nvariables = n;
	size = rc->name_size;
	p = rc->names;

	for (i = 0; i < n; i++) {
		rv[i].capture = 2 * ((p[0] << 8) + p[1]);

		name.data = &p[2];
		name.len = ngx_strlen(name.data);

		v = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
		if (v == NULL) {
			return NULL;
		}

		rv[i].index = ngx_http_get_variable_index(cf, &name);
		if (rv[i].index == NGX_ERROR) {
			return NULL;
		}

		v->get_handler = ngx_http_variable_not_found;

		p += size;
	}
#endif
	return re;
#endif
}


ngx_int_t my_ngx_http_regex_exec_conf(my_ngx_pool_t *pool, ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s)
{
	ngx_int_t		rc;//index;
	ngx_uint_t		len;//i, n, 
#if 0
	ngx_http_variable_value_t  *vv;
	ngx_http_core_main_conf_t  *cmcf;
#endif

	if (re->ncaptures) {
		len = re->ncaptures;

		if (r->captures == NULL) {
			//r->captures = ngx_palloc(pool, len * sizeof(int));
			r->captures = ngx_palloc(pool, len * sizeof(int));
			if (r->captures == NULL) {
				return NGX_ERROR;
			}
		}

	} else {
		len = 0;
	}

	rc = ngx_regex_exec(re->regex, s, r->captures, len);/*This macro call pcre_exec*/

	if (rc == NGX_REGEX_NO_MATCHED) {
		return NGX_DECLINED;
	}

	if (rc < 0) {
#if 0
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
					  ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
					  rc, s, &re->name);
#endif
		return NGX_ERROR;
	}
#if 0
	for (i = 0; i < re->nvariables; i++) {

		n = re->variables[i].capture;
		index = re->variables[i].index;
		vv = &r->variables[index];

		vv->len = r->captures[n + 1] - r->captures[n];
		vv->valid = 1;
		vv->no_cacheable = 0;
		vv->not_found = 0;
		vv->data = &s->data[r->captures[n]];
	}
#endif
	r->ncaptures = rc * 2;
	r->captures_data = s->data;

	return NGX_OK;
}


ngx_int_t my_ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s)
{
	ngx_int_t		rc;//index;
	ngx_uint_t		len;//i, n, 
#if 0
	ngx_http_variable_value_t  *vv;
	ngx_http_core_main_conf_t  *cmcf;
#endif

	if (re->ncaptures) {
		len = re->ncaptures;

		if (r->captures == NULL) {
			r->captures = ngx_palloc(r->pool, len * sizeof(int));
			if (r->captures == NULL) {
				return NGX_ERROR;
			}
		}

	} else {
		len = 0;
	}

	rc = ngx_regex_exec(re->regex, s, r->captures, len);/*This macro call pcre_exec*/

	if (rc == NGX_REGEX_NO_MATCHED) {
		return NGX_DECLINED;
	}

	if (rc < 0) {
#if 0
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
					  ngx_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
					  rc, s, &re->name);
#endif
		return NGX_ERROR;
	}
#if 0
	for (i = 0; i < re->nvariables; i++) {

		n = re->variables[i].capture;
		index = re->variables[i].index;
		vv = &r->variables[index];

		vv->len = r->captures[n + 1] - r->captures[n];
		vv->valid = 1;
		vv->no_cacheable = 0;
		vv->not_found = 0;
		vv->data = &s->data[r->captures[n]];
	}
#endif
	r->ncaptures = rc * 2;
	r->captures_data = s->data;

	return NGX_OK;
}




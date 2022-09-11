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
 * HTTP request and response parser and upstream header process routines.
 */
#include <vnet/http_proxy/nginx/include/ngx_http.h>
#include <vnet/http_proxy/http_proxy.h>
#include <vnet/http_proxy/http_parse.h>

static ngx_hash_t  headers_in_hash;
ngx_hash_t  upstream_headers_in_hash;


static ngx_int_t
ngx_http_upstream_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  *ho, **ph;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_content_type(ngx_http_request_t *r, ngx_table_elt_t *h,
	ngx_uint_t offset)
{
	u_char	*p, *last;

	r->headers_out.content_type_len = h->value.len;
	r->headers_out.content_type = h->value;
	r->headers_out.content_type_lowcase = NULL;

	for (p = h->value.data; *p; p++) {

		if (*p != ';') {
			continue;
		}

		last = p;

		while (*++p == ' ') { /* void */ }

		if (*p == '\0') {
			return NGX_OK;
		}

		if (ngx_strncasecmp(p, (u_char *) "charset=", 8) != 0) {
			continue;
		}

		p += 8;

		r->headers_out.content_type_len = last - h->value.data;

		if (*p == '"') {
			p++;
		}

		last = h->value.data + h->value.len;

		if (*(last - 1) == '"') {
			last--;
		}

		r->headers_out.charset.len = last - p;
		r->headers_out.charset.data = p;

		return NGX_OK;
	}

	return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_content_length(ngx_http_request_t *r,
	ngx_table_elt_t *h, ngx_uint_t offset)
{
	ngx_http_upstream_t  *u;

	u = r->upstream;

	u->headers_in.content_length = h;
	u->headers_in.content_length_n = ngx_atoof(h->value.data, h->value.len);

	return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
	ngx_uint_t offset)
{
	ngx_table_elt_t  **ph;

	ph = (ngx_table_elt_t **) ((char *) &r->upstream->headers_in + offset);

	if (*ph == NULL) {
		*ph = h;
	}

	return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_process_last_modified(ngx_http_request_t *r,
	ngx_table_elt_t *h, ngx_uint_t offset)
{
	ngx_http_upstream_t  *u;

	u = r->upstream;

	u->headers_in.last_modified = h;
	u->headers_in.last_modified_time = ngx_parse_http_time(h->value.data,
														   h->value.len);

	return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_rewrite_location(ngx_http_request_t *r, ngx_table_elt_t *h,
	ngx_uint_t offset)
{
	ngx_int_t		  rc;
	ngx_table_elt_t  *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	if (r->upstream->rewrite_redirect) {
		rc = r->upstream->rewrite_redirect(r, ho, 0);

		if (rc == NGX_DECLINED) {
			return NGX_OK;
		}

		if (rc == NGX_OK) {
			r->headers_out.location = ho;

			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						   "rewritten location: \"%V\"", &ho->value);
		}

		return rc;
	}

	if (ho->value.data[0] != '/') {
		r->headers_out.location = ho;
	}

	/*
	 * we do not set r->headers_out.location here to avoid handling
	 * relative redirects in ngx_http_header_filter()
	 */

	return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_ignore_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
	ngx_uint_t offset)
{
	return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_rewrite_refresh(ngx_http_request_t *r, ngx_table_elt_t *h,
	ngx_uint_t offset)
{
	u_char			 *p;
	ngx_int_t		  rc;
	ngx_table_elt_t  *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	if (r->upstream->rewrite_redirect) {

		p = ngx_strcasestrn(ho->value.data, "url=", 4 - 1);

		if (p) {
			rc = r->upstream->rewrite_redirect(r, ho, p + 4 - ho->value.data);

		} else {
			return NGX_OK;
		}

		if (rc == NGX_DECLINED) {
			return NGX_OK;
		}

		if (rc == NGX_OK) {
			r->headers_out.refresh = ho;

			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						   "rewritten refresh: \"%V\"", &ho->value);
		}

		return rc;
	}

	r->headers_out.refresh = ho;

	return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_process_set_cookie(ngx_http_request_t *r, ngx_table_elt_t *h,
	ngx_uint_t offset)
{
	ngx_array_t 		  *pa;
	ngx_table_elt_t 	 **ph;
	ngx_http_upstream_t   *u;

	u = r->upstream;
	pa = &u->headers_in.cookies;

	if (pa->elts == NULL) {
		if (ngx_array_init(pa, r->pool, 1, sizeof(ngx_table_elt_t *)) != NGX_OK)
		{
			return NGX_ERROR;
		}
	}

	ph = ngx_array_push(pa);
	if (ph == NULL) {
		return NGX_ERROR;
	}

	*ph = h;

#if (NGX_HTTP_CACHE)
	if (!(u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_SET_COOKIE)) {
		u->cacheable = 0;
	}
#endif

	return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_rewrite_set_cookie(ngx_http_request_t *r, ngx_table_elt_t *h,
	ngx_uint_t offset)
{
	ngx_int_t		  rc;
	ngx_table_elt_t  *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	if (r->upstream->rewrite_cookie) {
		rc = r->upstream->rewrite_cookie(r, ho);

		if (rc == NGX_DECLINED) {
			return NGX_OK;
		}

#if (NGX_DEBUG)
		if (rc == NGX_OK) {
			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
						   "rewritten cookie: \"%V\"", &ho->value);
		}
#endif

		return rc;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h,
	ngx_uint_t offset)
{
	r->upstream->headers_in.connection = h;

	if (ngx_strlcasestrn(h->value.data, h->value.data + h->value.len,
						 (u_char *) "close", 5 - 1)
		!= NULL)
	{
		r->upstream->headers_in.connection_close = 1;
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_process_vary(ngx_http_request_t *r,
	ngx_table_elt_t *h, ngx_uint_t offset)
{
	ngx_http_upstream_t  *u;

	u = r->upstream;
	u->headers_in.vary = h;

#if (NGX_HTTP_CACHE)

	if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_VARY) {
		return NGX_OK;
	}

	if (r->cache == NULL) {
		return NGX_OK;
	}

	if (h->value.len > NGX_HTTP_CACHE_VARY_LEN
		|| (h->value.len == 1 && h->value.data[0] == '*'))
	{
		u->cacheable = 0;
	}

	r->cache->vary = h->value;

#endif

	return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_copy_multi_header_lines(ngx_http_request_t *r,
	ngx_table_elt_t *h, ngx_uint_t offset)
{
	ngx_array_t 	 *pa;
	ngx_table_elt_t  *ho, **ph;

	pa = (ngx_array_t *) ((char *) &r->headers_out + offset);

	if (pa->elts == NULL) {
		if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *)) != NGX_OK)
		{
			return NGX_ERROR;
		}
	}

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	ph = ngx_array_push(pa);
	if (ph == NULL) {
		return NGX_ERROR;
	}

	*ph = ho;

	return NGX_OK;
}

static ngx_int_t
ngx_http_upstream_process_transfer_encoding(ngx_http_request_t *r,
	ngx_table_elt_t *h, ngx_uint_t offset)
{
	r->upstream->headers_in.transfer_encoding = h;

	if (ngx_strlcasestrn(h->value.data, h->value.data + h->value.len,
						 (u_char *) "chunked", 7 - 1)
		!= NULL)
	{
		r->upstream->headers_in.chunked = 1;
	}

	return NGX_OK;
}



static ngx_int_t
ngx_http_upstream_copy_last_modified(ngx_http_request_t *r, ngx_table_elt_t *h,
	ngx_uint_t offset)
{
	ngx_table_elt_t  *ho;

	ho = ngx_list_push(&r->headers_out.headers);
	if (ho == NULL) {
		return NGX_ERROR;
	}

	*ho = *h;

	r->headers_out.last_modified = ho;
	r->headers_out.last_modified_time =
									r->upstream->headers_in.last_modified_time;

	return NGX_OK;
}

static ngx_http_upstream_header_t  myngx_http_upstream_headers_in[] = {

    { ngx_string("Status"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, status),
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("Content-Type"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, content_type),
                 ngx_http_upstream_copy_content_type, 0, 1 },

    { ngx_string("Content-Length"),
                 ngx_http_upstream_process_content_length, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("Date"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, date),
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, date), 0 },

    { ngx_string("Last-Modified"),
                 ngx_http_upstream_process_last_modified, 0,
                 ngx_http_upstream_copy_last_modified, 0, 0 },

    { ngx_string("ETag"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, etag),
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, etag), 0 },

    { ngx_string("Server"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, server),
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, server), 0 },

    { ngx_string("WWW-Authenticate"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, www_authenticate),
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("Location"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, location),
                 ngx_http_upstream_rewrite_location, 0, 0 },

    { ngx_string("Refresh"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_rewrite_refresh, 0, 0 },

    { ngx_string("Set-Cookie"),
                 ngx_http_upstream_process_set_cookie,
                 offsetof(ngx_http_upstream_headers_in_t, cookies),
                 ngx_http_upstream_rewrite_set_cookie, 0, 1 },

    { ngx_string("Content-Disposition"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_copy_header_line, 0, 1 },
#if 0
    { ngx_string("Cache-Control"),
                 ngx_http_upstream_process_cache_control, 0,
                 ngx_http_upstream_copy_multi_header_lines,
                 offsetof(ngx_http_headers_out_t, cache_control), 1 },
    { ngx_string("Expires"),
                 ngx_http_upstream_process_expires, 0,
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, expires), 1 },

    { ngx_string("Accept-Ranges"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, accept_ranges),
                 ngx_http_upstream_copy_allow_ranges,
                 offsetof(ngx_http_headers_out_t, accept_ranges), 1 },
#endif

    { ngx_string("Content-Range"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, content_range), 0 },

    { ngx_string("Connection"),
                 ngx_http_upstream_process_connection, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("Keep-Alive"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("Vary"),
                 ngx_http_upstream_process_vary, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("Link"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_copy_multi_header_lines,
                 offsetof(ngx_http_headers_out_t, link), 0 },
#if 0
    { ngx_string("X-Accel-Expires"),
                 ngx_http_upstream_process_accel_expires, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("X-Accel-Redirect"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, x_accel_redirect),
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("X-Accel-Limit-Rate"),
                 ngx_http_upstream_process_limit_rate, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("X-Accel-Buffering"),
                 ngx_http_upstream_process_buffering, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("X-Accel-Charset"),
                 ngx_http_upstream_process_charset, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },
#endif
    { ngx_string("Transfer-Encoding"),
                 ngx_http_upstream_process_transfer_encoding, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },
#if 0
#if (NGX_HTTP_GZIP)
    { ngx_string("Content-Encoding"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, content_encoding),
                 ngx_http_upstream_copy_content_encoding, 0, 0 },
#endif
#endif
    { ngx_null_string, NULL, 0, NULL, 0, 0 }
};


static const char *parser_state_str(PARSE_STATE_e ps)
{
	switch(ps)
	{
	case PARSE_STATE_REQ_START:	return "httprequeststart";
	case PARSE_STATE_RESP_START:	return "httpresponsestart";
	case PARSE_STATE_HEADER_START:		return "httpheaderstart";
	case PARSE_STATE_BODY_START:		return "httpbodystart";
	default:				return "Unknown";
	}
}

static int http_parse_response_body(dproxy_http_upstream_t *upstream, int data_len, ngx_buf_t *buf, unsigned char **processed_data_end_position)
{
	if(!upstream->is_chunked) {
		if(!upstream->content_length_exists) {
			return EHTTP_MESSAGE_PARSE_CONTINUE;
		}

		if (data_len > 0) {
			upstream->current_body_length += data_len;
		}
		if( upstream->current_body_length >= upstream->content_length){
			*processed_data_end_position = buf->last;
			htp_req_debug_print("body completed, length is %d, recved: %d\n",upstream->content_length, upstream->current_body_length );
			return EHTTP_MESSAGE_PARSE_COMPLETED;
		} else if(upstream->current_body_length < upstream->content_length){
			*processed_data_end_position = buf->last;
			htp_req_debug_print("body parse in-completed : %d < %d\n" ,  upstream->current_body_length, 	upstream->content_length);
			return EHTTP_MESSAGE_PARSE_CONTINUE;
		} else {
#if	0
			htp_resp_debug_print("body length %d > %d\n",data_parse->current_body_length, data_parse->content_length );
			*processed_data_end_position = buf->last - (data_parse->current_body_length -  data_parse->content_length);
			htp_resp_debug_print("extra data after message body length is %d\n",data_parse->current_body_length -	data_parse->content_length);
#endif
			return EHTTP_MESSAGE_PARSE_COMPLETED;
		}
	} else {
#if 0
		*processed_data_end_position = buf->start;
		while(*processed_data_end_position < buf->last)
		{
			int res_result = 0;
			buf->pos = *processed_data_end_position;
			res_result = ngx_http_proxy_parse_chunked(&data_parse->req, buf);
			switch(res_result) {
			case NGX_DONE:
				*processed_data_end_position = buf->last;
				return EHTTP_MESSAGE_PARSE_COMPLETED;
			case NGX_OK :
#if 1
				htp_resp_debug_print("%s: parse return OK ngx state: %d cur state: %s, chunk size: %u, buf size: %u\n", __FUNCTION__, 
						(int)data_parse->req.state, parser_state_str(data_parse->current_parse_state), data_parse->req.size, (unsigned int)(buf->last-buf->start));
#endif
				if (buf->last - buf->pos >= data_parse->req.size) {
					*processed_data_end_position = buf->pos + data_parse->req.size;
					data_parse->req.size = 0;
					htp_resp_debug_print("%s: 0x%x, 0x%x\n", __FUNCTION__, *(buf->start), *(*processed_data_end_position) );
				} else {
					data_parse->req.size -= (buf->last - buf->pos);
					*processed_data_end_position = buf->last;
				}
				break;
			case NGX_AGAIN:
				htp_resp_debug_print("%s: chunk parse return again ngx state: %d cur state: %s, chunk size: %u\n", __FUNCTION__, (int)data_parse->req.state, parser_state_str(data_parse->current_parse_state), data_parse->req.size);
				*processed_data_end_position = buf->pos;
				break;
			default:
				htp_resp_debug_print("%s: ngx_http_proxy_parse_chunked error: %d\n", __FUNCTION__, res_result);
				return EHTTP_MESSAGE_PARSE_ERROR;
			}
		}
		return EHTTP_MESSAGE_PARSE_CONTINUE;
#endif
	    return EHTTP_MESSAGE_PARSE_COMPLETED;
	}
}


static int http_parse_body(http_parse_data_t *data_parse, vlib_buffer_t *mb, int data_len, ngx_buf_t *buf, unsigned char **processed_data_end_position)
{
	if(!data_parse->is_chunked) {
		if(!data_parse->content_length_exists) {
			return EHTTP_MESSAGE_PARSE_CONTINUE;
		}

		if (data_parse->body_start_mb == NULL && (data_parse->req.method == NGX_HTTP_POST || data_parse->req.method == NGX_HTTP_PUT)) {
			htp_req_debug_print("%d Seen the body, let's start to record it\n", __LINE__);
			data_parse->body_start_mb = mb;
			data_parse->body_start_pos = (char *)buf->start;
		}

		if (data_len > 0) {
			data_parse->current_body_length += data_len;
		}
		if( data_parse->current_body_length >= data_parse->content_length){
			*processed_data_end_position = buf->last;
			htp_req_debug_print("body completed, length is %d, recved: %d\n",data_parse->content_length, data_parse->current_body_length );
			return EHTTP_MESSAGE_PARSE_COMPLETED;
		} else if(data_parse->current_body_length < data_parse->content_length){
			*processed_data_end_position = buf->last;
			htp_req_debug_print("body parse in-completed : %d < %d\n" ,  data_parse->current_body_length, 	data_parse->content_length);
			return EHTTP_MESSAGE_PARSE_CONTINUE;
		} else {
#if	0
			htp_req_debug_print("body length %d > %d\n",data_parse->current_body_length, data_parse->content_length );
			*processed_data_end_position = buf->last - (data_parse->current_body_length -  data_parse->content_length);
			htp_req_debug_print("extra data after message body length is %d\n",data_parse->current_body_length -	data_parse->content_length);
#endif
			return EHTTP_MESSAGE_PARSE_COMPLETED;
		}
	} else {
#if 0
		*processed_data_end_position = buf->start;
		while(*processed_data_end_position < buf->last)
		{
			int res_result = 0;
			buf->pos = *processed_data_end_position;
			res_result = ngx_http_proxy_parse_chunked(&data_parse->req, buf);
			switch(res_result) {
			case NGX_DONE:
				*processed_data_end_position = buf->last;
				return EHTTP_MESSAGE_PARSE_COMPLETED;
			case NGX_OK :
#if 1
				htp_req_debug_print("%s: parse return OK ngx state: %d cur state: %s, chunk size: %u, buf size: %u\n", __FUNCTION__, 
						(int)data_parse->req.state, parser_state_str(data_parse->current_parse_state), data_parse->req.size, (unsigned int)(buf->last-buf->start));
#endif
				if (buf->last - buf->pos >= data_parse->req.size) {
					*processed_data_end_position = buf->pos + data_parse->req.size;
					data_parse->req.size = 0;
					htp_req_debug_print("%s: 0x%x, 0x%x\n", __FUNCTION__, *(buf->start), *(*processed_data_end_position) );
				} else {
					data_parse->req.size -= (buf->last - buf->pos);
					*processed_data_end_position = buf->last;
				}
				break;
			case NGX_AGAIN:
				htp_req_debug_print("%s: chunk parse return again ngx state: %d cur state: %s, chunk size: %u\n", __FUNCTION__, (int)data_parse->req.state, parser_state_str(data_parse->current_parse_state), data_parse->req.size);
				*processed_data_end_position = buf->pos;
				break;
			default:
				htp_req_debug_print("%s: ngx_http_proxy_parse_chunked error: %d\n", __FUNCTION__, res_result);
				return EHTTP_MESSAGE_PARSE_ERROR;
			}
		}
		return EHTTP_MESSAGE_PARSE_CONTINUE;
#endif
	    return EHTTP_MESSAGE_PARSE_COMPLETED;
	}
}

static void dproxy_http_set_keepalive(ngx_http_request_t *r)
{
	FUNC_TRACE;
	switch (r->headers_in.connection_type) {
		case 0:
			htp_req_debug_print("%s:%d r->headers_in.connection_type value is 0\n");
			r->keepalive = (r->http_version > NGX_HTTP_VERSION_10);
			break;
		case NGX_HTTP_CONNECTION_CLOSE:
			htp_req_debug_print("%s:%d r->headers_in.connection_type value is 1\n");
			r->keepalive = 0;
			break;
		case NGX_HTTP_CONNECTION_KEEP_ALIVE:
			htp_req_debug_print("%s:%d r->headers_in.connection_type value is 2\n");
			r->keepalive = 1;
			break;
	}
}

int http_parse_request(vlib_buffer_t *mb, unsigned char *data, int data_len, http_parse_data_t *data_parse, unsigned char **processed_data_end_position)
{
	int req_result;
	int req_len = 0;
	ngx_buf_t buf;
	ngx_table_elt_t *h;
	ngx_http_header_t          *hh;
	ngx_http_request_t         *r;
	if(!data || data_len <= 0 || data_parse == NULL || !processed_data_end_position) {
		htp_req_debug_print("%s Parameters wrong, return EHTTP_MESSAGE_PARSE_PARAM_ERROR\n", __func__);
		return EHTTP_MESSAGE_PARSE_PARAM_ERROR;
	}

	buf.start = buf.pos = data;
	buf.last = data + data_len;
	r = &data_parse->req;
	switch (data_parse->current_parse_state) {
		/* start to parse request_line */
		case PARSE_STATE_REQ_START:

			req_result = ngx_http_parse_request_line(&data_parse->req, &buf);
			*processed_data_end_position = buf.pos;
			switch(req_result) {
				case NGX_OK :
					data_parse->current_parse_state = PARSE_STATE_HEADER_START;
					htp_req_debug_print("request_line parse completed : %s\n", parser_state_str(data_parse->current_parse_state));
					req_len = data_parse->req.request_end + 2 - data ; 
					if(req_len < data_len) {
						htp_req_debug_print("data remained: %d\n", data_len - req_len );
					}

					if (ngx_list_init(&r->headers_in.headers, r->pool, 20, sizeof(ngx_table_elt_t)) != NGX_OK) {
						htp_req_debug_print("request_line parse error : %s, failed to ngx_list_init headers_in.headers\n", parser_state_str(data_parse->current_parse_state));
						return EHTTP_MESSAGE_PARSE_ERROR;
					}
					/*set the r->method_name so prepare_request will use the same method to upstream*/
					r->request_line.len = r->request_end - r->request_start;
					r->request_line.data = r->request_start;
					r->method_name.len =  r->method_end - r->request_start + 1;
					r->method_name.data = r->request_line.data;
					if (ngx_http_process_request_uri(r) != NGX_OK) {
						return EHTTP_MESSAGE_PARSE_ERROR;
					}
					return EHTTP_REQUEST_LINE_PARSE_COMPLETED;
					
				case NGX_AGAIN:
					htp_req_debug_print("request_line in-completed : %d\n" , (int)data_parse->req.state);
					htp_req_debug_print("request_line parse continue : %s\n", parser_state_str(data_parse->current_parse_state));
					return EHTTP_MESSAGE_PARSE_CONTINUE;
					
				default:
					htp_req_debug_print("request_line parse error : %s\n", parser_state_str(data_parse->current_parse_state));
					return EHTTP_MESSAGE_PARSE_ERROR;
			}

		/* request_line done, and star to parse header */
		case PARSE_STATE_HEADER_START:
			req_result = ngx_http_parse_header_line(&data_parse->req, &buf, 1);
			ngx_int_t find_host_ret;
			*processed_data_end_position = buf.pos;
			switch(req_result) {
				case NGX_OK :
					req_len = data_parse->req.header_end + 2 - (u_char *)data; 
					data_parse->current_parse_state = PARSE_STATE_HEADER_START;
					//dproxy_http_request_header_filed_dump(data_parse->req.lowcase_header, data_parse->req.header_start, data_parse->req.header_end);
					if (data_parse->req.invalid_header) {
						return EHTTP_HEADER_LINE_PARSE_COMPLETED;
					}
					/* a header line has been parsed successfully */
					h = ngx_list_push(&data_parse->req.headers_in.headers);
					if (h == NULL) {
						htp_req_debug_print("ngx_list_push data_parse->req.headers_in.headers failed\n");
						return EHTTP_MESSAGE_PARSE_ERROR;
					}

					h->hash = r->header_hash;
					//拷贝name:value中的name到key�?,name后面的冒号被用\0替换�?
					h->key.len = r->header_name_end - r->header_name_start;
					h->key.data = r->header_name_start;
					h->key.data[h->key.len] = '\0';

					//拷贝name:value中的value到value中，value后的换行符被用\0替换�?
					h->value.len = r->header_end - r->header_start;
					h->value.data = r->header_start;
					h->value.data[h->value.len] = '\0';

					//h->lowcase_key = my_ngx_pnalloc(data_parse->req_pool, h->key.len);
					h->lowcase_key = ngx_pnalloc(data_parse->req.pool, h->key.len);
					if (h->lowcase_key == NULL) {
						htp_req_debug_print("(%s:%d) my_ngx_pnalloc failed\n", __func__, __LINE__);
						return EHTTP_MESSAGE_PARSE_ERROR;
					}

					if (h->key.len == r->lowcase_index) {
						ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
					} else {
						ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
					}

					hh = ngx_hash_find(&headers_in_hash, h->hash, h->lowcase_key, h->key.len);
					if (strncmp((const char *)h->lowcase_key, "host", strlen("host")) == 0) {
						find_host_ret = myngx_http_process_host(r, h, hh->offset, data_parse);
						if (find_host_ret != NGX_OK) {
							return EHTTP_MESSAGE_PARSE_ERROR;
						}
					} else {
						if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
							htp_req_debug_print("(%s:%d) hh->handler failed\n", __func__, __LINE__);
							return EHTTP_MESSAGE_PARSE_ERROR;
						}
					}
					// check content-lengthֵ
					if(data_parse->req.lowcase_index  == (sizeof("content-length")/sizeof(char) - 1) &&
						memcmp(data_parse->req.lowcase_header, "content-length", data_parse->req.lowcase_index )==0) {
							data_parse->content_length_exists = 1;
							// atoi will stop on '\r'
							data_parse->content_length = atoi((const char *)data_parse->req.header_start);
							htp_req_debug_print("content-length is: %d\n", data_parse->content_length);
							if(data_parse->content_length < 0)
							{
								htp_req_debug_print("content_length invalid: %d\n", data_parse->content_length );
								data_parse->current_parse_state = PARSE_STATE_REQ_START;
								return EHTTP_MESSAGE_PARSE_ERROR;
							}
					}
					// check chunked
					if(data_parse->req.lowcase_index  == (sizeof("transfer-encoding")/sizeof(char) - 1) &&
						memcmp(data_parse->req.lowcase_header, "transfer-encoding", data_parse->req.lowcase_index )==0) {
							htp_req_debug_print("transfer-encoding found\n");
							if(data_parse->req.header_end - data_parse->req.header_start  == sizeof("chunked") - 1 &&
								strncasecmp((const char *)data_parse->req.header_start, "chunked", sizeof("chunked") - 1) == 0)
								data_parse->is_chunked = 1;
					}
					htp_req_debug_print("header parse completed : %s\n", parser_state_str(data_parse->current_parse_state));
					if(req_len < data_len){
						htp_req_debug_print("header_line data remained: %d\n", data_len - req_len);
					}
					return EHTTP_HEADER_LINE_PARSE_COMPLETED;

				case NGX_HTTP_PARSE_HEADER_DONE :
					req_len = *processed_data_end_position - data; 
					data_parse->current_parse_state = PARSE_STATE_BODY_START;
					//dproxy_http_counter_header_parse_done();
					htp_req_debug_print("header parse header_done : %s\n", parser_state_str(data_parse->current_parse_state));
					if(req_len < data_len) {
						htp_req_debug_print("header done data remained: %d\n",data_len - req_len);
					}
					dproxy_http_set_keepalive(&data_parse->req);
					if(data_parse->is_chunked) {
						data_parse->req.state = 0; //sw_chunk_start
					} else {
						if(data_parse->content_length == 0){
							data_parse->current_parse_state = PARSE_STATE_REQ_START;
							return EHTTP_HEADER_DONE_NOBY_PARSE_COMPLETED;
						} else {
						}
					}
					return EHTTP_HEADER_DONE_PARSE_COMPLETED;
				case NGX_AGAIN:
					htp_req_debug_print("header parse ngx state : %d\n" , (int)data_parse->req.state);
					htp_req_debug_print("header parse current state: %s\n", parser_state_str(data_parse->current_parse_state));
					return EHTTP_MESSAGE_PARSE_CONTINUE;
				default:
					htp_req_debug_print("ngx_http_parse_header_line return error, reset state\n");
					return EHTTP_MESSAGE_PARSE_ERROR;
			}
		case PARSE_STATE_BODY_START:
			return http_parse_body(data_parse, mb, data_len, &buf, processed_data_end_position);
		default:
			htp_req_debug_print("%s: invalid parser state: %s\n", __FUNCTION__, parser_state_str(data_parse->current_parse_state));
			return EHTTP_MESSAGE_PARSE_ERROR;
	}
	return EHTTP_MESSAGE_PARSE_ERROR;
}


int http_parse_response(unsigned char *data, int data_len, dproxy_http_upstream_t *upstream, unsigned char **processed_data_end_position)
{
	int res_result;
	int res_len = 0;
	ngx_buf_t buf;
	ngx_table_elt_t *h;
	ngx_http_upstream_header_t          *hh;
	ngx_http_request_t         *r;
	http_parse_data_t *data_parse = upstream->http_data;

	if(!data || data_len <= 0 || data_parse == NULL || !processed_data_end_position) {
		htp_resp_debug_print("%s Parameters wrong, return EHTTP_MESSAGE_PARSE_PARAM_ERROR\n", __func__);
		return EHTTP_MESSAGE_PARSE_PARAM_ERROR;
	}

	buf.start = buf.pos = data;
	buf.last = data + data_len;
	r = &data_parse->req;
	switch (upstream->current_parse_state) {
		/* start to parse request_line */
		case PARSE_STATE_RESP_START:

			res_result = ngx_http_parse_status_line(&data_parse->req, &buf, &data_parse->status);
			*processed_data_end_position = buf.pos;
			switch(res_result) {
				case NGX_OK :
					upstream->current_parse_state = PARSE_STATE_HEADER_START;
					htp_resp_debug_print("status_line parse completed : %s\n", parser_state_str(upstream->current_parse_state));
					res_len = *processed_data_end_position - data ;
					if(res_len < data_len) {
						htp_resp_debug_print("data remained: %d\n", data_len - res_len );
					}

					if (ngx_list_init(&r->upstream->headers_in.headers, r->pool, 20, sizeof(ngx_table_elt_t)) != NGX_OK) {
						htp_resp_debug_print("request_line parse error : %s, failed to ngx_list_init headers_in.headers\n", parser_state_str(upstream->current_parse_state));
						return EHTTP_MESSAGE_PARSE_ERROR;
					}

					if (data_parse->status.http_version < NGX_HTTP_VERSION_11) {
						r->upstream->headers_in.connection_close = 1;
					}

					/*set u->headers_in.status_n to status.code from upstream then
					* dproxy_http_upstream_process_headers will give it to r->header_out.status,
					* set u->headers_in.status_line.len = 0 so don't need memory for status_line.data
					*
					*/
					r->upstream->headers_in.status_n = data_parse->status.code;
					r->upstream->headers_in.status_line.len = 0;
					return EHTTP_REQUEST_LINE_PARSE_COMPLETED;

				case NGX_AGAIN:
					htp_resp_debug_print("status_line in-completed : %d\n" , (int)data_parse->req.state);
					htp_resp_debug_print("status_line parse continue : %s\n", parser_state_str(upstream->current_parse_state));
					return EHTTP_MESSAGE_PARSE_CONTINUE;
				default:
					htp_resp_debug_print("status_line parse error : %s\n", parser_state_str(upstream->current_parse_state));
					return EHTTP_MESSAGE_PARSE_ERROR;
			}

		/* request_line done, and star to parse header */
		case PARSE_STATE_HEADER_START:
			res_result = ngx_http_parse_header_line(&data_parse->req, &buf, 1);
			*processed_data_end_position = buf.pos;
			switch(res_result) {
				case NGX_OK :
					res_len = *processed_data_end_position - data ;
					upstream->current_parse_state = PARSE_STATE_HEADER_START;
					//dproxy_http_request_header_filed_dump(data_parse->req.lowcase_header, data_parse->req.header_start, data_parse->req.header_end);
					if (data_parse->req.invalid_header) {
						return EHTTP_HEADER_LINE_PARSE_COMPLETED;
					}
					/* a header line has been parsed successfully */
					h = ngx_list_push(&data_parse->req.upstream->headers_in.headers);
					if (h == NULL) {
						htp_resp_debug_print("ngx_list_push data_parse->req.headers_in.headers failed\n");
						return EHTTP_MESSAGE_PARSE_ERROR;
					}

					h->hash = r->header_hash;
					//拷贝name:value中的name到key�?,name后面的冒号被用\0替换�?
					h->key.len = r->header_name_end - r->header_name_start;
					h->value.len = r->header_end - r->header_start;

					//h->key.data = my_ngx_pnalloc(data_parse->req_pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
					h->key.data = ngx_pnalloc(data_parse->req.pool, h->key.len + 1 + h->value.len + 1 + h->key.len);
					if (h->key.data == NULL) {
						h->hash = 0;
						return EHTTP_MESSAGE_PARSE_ERROR;
					}

					h->value.data = h->key.data + h->key.len + 1;
					h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

					ngx_memcpy(h->key.data, r->header_name_start, h->key.len);
					h->key.data[h->key.len] = '\0';
					ngx_memcpy(h->value.data, r->header_start, h->value.len);
					h->value.data[h->value.len] = '\0';

					if (h->key.len == r->lowcase_index) {
						ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);
					} else {
						ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
					}

					hh = ngx_hash_find(&upstream_headers_in_hash, h->hash, h->lowcase_key, h->key.len);
					if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
						htp_resp_debug_print("(%s:%d) hh->handler failed\n", __func__, __LINE__);
						return EHTTP_MESSAGE_PARSE_ERROR;
					}

					htp_resp_debug_print("header parse completed : %s\n", parser_state_str(upstream->current_parse_state));
					if(res_len < data_len){
						htp_resp_debug_print("header_line data remained: %d\n", data_len - res_len);
					}
					return EHTTP_HEADER_LINE_PARSE_COMPLETED;

				case NGX_HTTP_PARSE_HEADER_DONE :
					res_len = *processed_data_end_position - data;
					upstream->current_parse_state = PARSE_STATE_BODY_START;
					//dproxy_http_counter_header_parse_done();
					htp_resp_debug_print("header parse header_done : %s\n", parser_state_str(upstream->current_parse_state));
					if(res_len < data_len) {
						htp_resp_debug_print("header done data remained: %d\n",data_len - res_len);
					}
					if(upstream->is_chunked) {
						data_parse->req.state = 0; //sw_chunk_start
					} else {
						upstream->content_length = r->upstream->headers_in.content_length_n;
						htp_resp_debug_print("%s:%d content_length %d\n", __func__, __LINE__, upstream->content_length);
						/*set upstream->content_length to 0 then return EHTTP_HEADER_DONE_NOBY_PARSE_COMPLETED
						* the dproxy_http_parse_response_message will split the remain data as the body
						*/
						upstream->content_length = 0;
						if(upstream->content_length == 0){
							upstream->current_parse_state = PARSE_STATE_RESP_START;
							return EHTTP_HEADER_DONE_NOBY_PARSE_COMPLETED;
						} else {
						}
					}
					return EHTTP_HEADER_DONE_PARSE_COMPLETED;
				case NGX_AGAIN:
					htp_resp_debug_print("header parse ngx state : %d\n" , (int)data_parse->req.state);
					htp_resp_debug_print("header parse current state: %s\n", parser_state_str(upstream->current_parse_state));
					return EHTTP_MESSAGE_PARSE_CONTINUE;
				default:
					htp_resp_debug_print("ngx_http_parse_header_line return error, reset state\n");
					return EHTTP_MESSAGE_PARSE_ERROR;
			}
		case PARSE_STATE_BODY_START:
			return http_parse_response_body(upstream, data_len, &buf, processed_data_end_position);
		default:
			htp_resp_debug_print("%s: invalid parser state: %s\n", __FUNCTION__, parser_state_str(upstream->current_parse_state));
			return EHTTP_MESSAGE_PARSE_ERROR;
	}
	return EHTTP_MESSAGE_PARSE_ERROR;
}

ngx_int_t myngx_http_init_headers_in_hash(ngx_pool_t *pool)
{
	ngx_array_t         headers_in;
	ngx_hash_key_t     *hk;
	ngx_hash_init_t     hash;
	ngx_http_header_t  *header;

	if (ngx_array_init(&headers_in, pool, 32, sizeof(ngx_hash_key_t))
		!= NGX_OK)
	{
		return NGX_ERROR;
	}

    for (header = ngx_http_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    ngx_cacheline_size = 64;
    hash.hash = &headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "headers_in_hash";
    hash.pool = pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t myngx_http_init_upstream_headers_in_hash(ngx_pool_t *pool)
{
	ngx_array_t         headers_in;
	ngx_hash_key_t     *hk;
	ngx_hash_init_t     hash;
	ngx_http_upstream_header_t  *header;

	if (ngx_array_init(&headers_in, pool, 32, sizeof(ngx_hash_key_t))
		!= NGX_OK)
	{
		return NGX_ERROR;
	}

    for (header = myngx_http_upstream_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    ngx_cacheline_size = 64;
    hash.hash = &upstream_headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "upstream_headers_in_hash";
    hash.pool = pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}



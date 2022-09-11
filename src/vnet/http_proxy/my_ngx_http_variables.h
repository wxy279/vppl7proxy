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

#ifndef _MY_NGX_HTTP_VARIABLES_H_INCLUDED_
#define _MY_NGX_HTTP_VARIABLES_H_INCLUDED_

#include <vnet/http_proxy/nginx/include/ngx_core.h>
#include <vnet/http_proxy/nginx/include/ngx_http.h>
#include <vnet/http_proxy/my_ngx_regex.h>
//Later should use vpp pool instead of malloc from libc
//#include "hili_ngx_palloc.h"

ngx_http_regex_t *my_ngx_http_regex_compile(my_ngx_pool_t *pool, ngx_regex_compile_t *rc);
ngx_int_t my_ngx_http_regex_exec_conf(my_ngx_pool_t *pool, ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s);
ngx_int_t my_ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s);

#endif /* _MY_NGX_HTTP_VARIABLES_H_INCLUDED_ */


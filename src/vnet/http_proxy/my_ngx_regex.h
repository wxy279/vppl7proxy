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
#ifndef _NGX_MY_REGEX_H_INCLUDED_
#define _NGX_MY_REGEX_H_INCLUDED_

#include <vnet/http_proxy/nginx/include/ngx_core.h>
#include <pcre.h>

typedef struct ngx_pool_s my_ngx_pool_t;
void my_ngx_regex_init(void);
ngx_int_t my_ngx_regex_compile(my_ngx_pool_t *pool, ngx_regex_compile_t *rc);
#endif /* _NGX_MY_REGEX_H_INCLUDED_*/

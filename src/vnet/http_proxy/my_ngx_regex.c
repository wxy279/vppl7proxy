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

#include <ngx_config.h>
#include <ngx_core.h>
#include <vnet/http_proxy/my_ngx_regex.h>

static void * ngx_libc_cdecl my_ngx_regex_malloc(size_t size);
static void ngx_libc_cdecl my_ngx_regex_free(void *p);

static my_ngx_pool_t  *ngx_pcre_pool;
//static ngx_list_t  *ngx_pcre_studies;

void
my_ngx_regex_init(void)
{
    pcre_malloc = my_ngx_regex_malloc;
    pcre_free = my_ngx_regex_free;
}


static ngx_inline void
my_ngx_regex_malloc_init(my_ngx_pool_t *pool)
{
    ngx_pcre_pool = pool;
}


static ngx_inline void
my_ngx_regex_malloc_done(void)
{
    ngx_pcre_pool = NULL;
}

ngx_int_t
my_ngx_regex_compile(my_ngx_pool_t *pool, ngx_regex_compile_t *rc)
{
    int               n, erroff;
    char             *p;
    pcre             *re;
    const char       *errstr;

    my_ngx_regex_malloc_init(pool);

    re = pcre_compile((const char *) rc->pattern.data, (int) rc->options,
                      &errstr, &erroff, NULL);

    /* ensure that there is no current pool */
    my_ngx_regex_malloc_done();

    if (re == NULL) {
        if ((size_t) erroff == rc->pattern.len) {
           rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\"",
                               errstr, &rc->pattern)
                      - rc->err.data;

        } else {
           rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\" at \"%s\"",
                               errstr, &rc->pattern, rc->pattern.data + erroff)
                      - rc->err.data;
        }

        return NGX_ERROR;
    }

    rc->regex = ngx_pcalloc(pool, sizeof(ngx_regex_t));
	//rc->regex = my_ngx_pcalloc(pool, sizeof(ngx_regex_t));
    if (rc->regex == NULL) {
        goto nomem;
    }

    rc->regex->code = re;

    /* do not study at runtime */
#if 0
    if (ngx_pcre_studies != NULL) {
        elt = ngx_list_push(ngx_pcre_studies);
        if (elt == NULL) {
            goto nomem;
        }

        elt->regex = rc->regex;
        elt->name = rc->pattern.data;
    }
#endif
    n = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &rc->captures);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_CAPTURECOUNT) failed: %d";
        goto failed;
    }

    if (rc->captures == 0) {
        return NGX_OK;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMECOUNT, &rc->named_captures);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMECOUNT) failed: %d";
        goto failed;
    }

    if (rc->named_captures == 0) {
        return NGX_OK;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMEENTRYSIZE, &rc->name_size);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMEENTRYSIZE) failed: %d";
        goto failed;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMETABLE, &rc->names);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMETABLE) failed: %d";
        goto failed;
    }

    return NGX_OK;

failed:

    rc->err.len = ngx_snprintf(rc->err.data, rc->err.len, p, &rc->pattern, n)
                  - rc->err.data;
    return NGX_ERROR;

nomem:

    rc->err.len = ngx_snprintf(rc->err.data, rc->err.len,
                               "regex \"%V\" compilation failed: no memory",
                               &rc->pattern)
                  - rc->err.data;
    return NGX_ERROR;
}

static void * ngx_libc_cdecl
my_ngx_regex_malloc(size_t size)
{
    my_ngx_pool_t      *pool;
    pool = ngx_pcre_pool;

    if (pool) {
        //return ngx_palloc(pool, size);
        return ngx_palloc(pool, size);
    }

    return NULL;
}


static void ngx_libc_cdecl
my_ngx_regex_free(void *p)
{
    return;
}


/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * mod_scrape.c --- Filter to scrape request or response bodies and write
 *                  them to disk. Use to demonstrate the risks of
 *                  unencrypted website connections.
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_uuid.h"

#include "ap_config.h"
#include "util_filter.h"
#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

static const char scrapeFilterName[] = "SCRAPE";
module AP_MODULE_DECLARE_DATA scrape_module;

typedef struct scrape_conf {
    const char *path; /* path where we save to */
    unsigned int path_set:1;
} scrape_conf;

typedef struct scrape_ctx {
    apr_file_t *file;
    apr_bucket_brigade *bb;
} scrape_ctx;

static apr_status_t scrape_name(ap_filter_t *f, const char *type, const char *encoding,
        apr_file_t **file)
{
    scrape_conf *dconf = ap_get_module_config(f->r->per_dir_config, &scrape_module);

    char buf[APR_UUID_FORMATTED_LENGTH + 1];
    char *newpath, *fname, *subtype, *params;
    apr_uuid_t uuid;
    int rv;

    apr_uuid_get(&uuid);
    apr_uuid_format(buf, &uuid);

    if (!encoding) {
        encoding = "identity";
    }

    if (type) {
        subtype = ap_strchr(type, '/');
        if (subtype) {
            subtype++;
            params = ap_strchr(subtype, ';');
            if (params) {
                params++;
                fname = apr_psprintf(f->r->pool, "%.*s_%.*s_%s_%s",
                        (int) (subtype - type - 1), type,
                        (int) (params - subtype - 1), subtype, encoding, buf);
            }
            else {
                fname = apr_psprintf(f->r->pool, "%.*s_%s_%s_%s",
                        (int) (subtype - type - 1), type, subtype, encoding,
                        buf);
            }
        }
        else {
            fname = apr_psprintf(f->r->pool, "%s_%s", encoding, buf);
        }
    }
    else {
        fname = apr_psprintf(f->r->pool, "%s_%s", encoding, buf);
    }

    rv = apr_filepath_merge(&newpath, dconf->path, fname,
            APR_FILEPATH_NOTRELATIVE | APR_FILEPATH_NOTABOVEROOT
                    | APR_FILEPATH_SECUREROOT, f->r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                "Could not merge '%s' into '%s', ignoring request", fname, dconf->path);
        return rv;
    }

    rv = apr_file_open(file, newpath, APR_FOPEN_WRITE | APR_FOPEN_CREATE,
            APR_FPROT_OS_DEFAULT, f->r->pool);
    if (APR_SUCCESS != rv) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                "Could not create file '%s', ignoring request", fname);
        return rv;
    }

    return APR_SUCCESS;
}

/**
 * Scrape buckets being written to the output filter stack.
 */
static apr_status_t scrape_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    apr_bucket *e;
    request_rec *r = f->r;
    scrape_ctx *ctx = f->ctx;
    apr_status_t rv = APR_SUCCESS;
    int seen_eos = 0;
    int skip = 0;

    /* first time in? create a context */
    if (!ctx) {

        /* we only scrape whole requests, not request fragments */
        if (f->r->main) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        ctx = f->ctx = apr_pcalloc(r->pool, sizeof(*ctx));
        ctx->bb = apr_brigade_create(r->pool, f->c->bucket_alloc);

        rv = scrape_name(f, apr_table_get(f->r->headers_out, "Content-Type"),
                apr_table_get(f->r->headers_out, "Content-Encoding"),
                &ctx->file);
        if (APR_SUCCESS != rv) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }
    }

    /* Do nothing if asked to filter nothing. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return ap_pass_brigade(f->next, bb);
    }

    while (APR_SUCCESS == rv && !APR_BRIGADE_EMPTY(bb)) {
        const char *data;
        apr_size_t size;

        e = APR_BRIGADE_FIRST(bb);

        /* EOS means we are done. */
        if (APR_BUCKET_IS_EOS(e)) {

            /* pass the EOS across */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            seen_eos = 1;

            /* pass what we have down the chain */
            rv = ap_pass_brigade(f->next, ctx->bb);
            continue;
        }

        /* A flush takes precedence over buffering */
        if (APR_BUCKET_IS_FLUSH(e)) {

            /* pass the flush bucket across */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

            /* pass what we have down the chain */
            rv = ap_pass_brigade(f->next, ctx->bb);
            continue;
        }

        /* metadata buckets are preserved as is */
        if (APR_BUCKET_IS_METADATA(e)) {
            /*
             * Remove meta data bucket from old brigade and insert into the
             * new.
             */
            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);
            continue;
        }

        /* let's read some data */
        if (APR_SUCCESS == (rv = apr_bucket_read(e, &data, &size,
                APR_BLOCK_READ))) {

            if (!skip) {
                apr_size_t written;
                rv = apr_file_write_full(ctx->file, data, size, &written);
                if (APR_SUCCESS != rv) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                            "Could not write to response file, scrape incomplete");
                    skip = 1;
                }
            }

            APR_BUCKET_REMOVE(e);
            APR_BRIGADE_INSERT_TAIL(ctx->bb, e);

        }

        /* pass what we have down the chain */
        rv = ap_pass_brigade(f->next, ctx->bb);
        if (rv) {
            /* should break out of the loop, since our write to the client
             * failed in some way. */
            continue;
        }

    }

    if (seen_eos || skip) {
        ap_remove_output_filter(f);
    }

    return rv;

}

/**
 * Scrape buckets being read from the input filter stack.
 */
static apr_status_t scrape_in_filter(ap_filter_t *f, apr_bucket_brigade *bb,
        ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
    apr_bucket *e;
    apr_status_t rv;
    scrape_ctx *ctx = f->ctx;

    int skip = 0;

    /* we only scrape whole requests, not request fragments */
    if (!ap_is_initial_req(f->r)) {
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* just get out of the way of things we don't want. */
    if (mode != AP_MODE_READBYTES) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* grab the data we do want */
    rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (rv != APR_SUCCESS || APR_BRIGADE_EMPTY(bb)) {
        return rv;
    }

    /* Do nothing if asked to filter nothing. */
    if (APR_BRIGADE_EMPTY(bb)) {
        return APR_SUCCESS;
    }

    for (e = APR_BRIGADE_FIRST(bb);
         e != APR_BRIGADE_SENTINEL(bb);
         e = APR_BUCKET_NEXT(e)) {

        const char *data;
        apr_size_t size = 0;

        /* pass metadata buckets through */
        if (APR_BUCKET_IS_METADATA(e)) {
            continue;
        }

        /* first time in? create a context */
        if (!ctx) {
            ctx = f->ctx = apr_pcalloc(f->r->pool, sizeof(*ctx));
            ctx->bb = apr_brigade_create(f->r->pool, f->c->bucket_alloc);

            rv = scrape_name(f, apr_table_get(f->r->headers_in, "Content-Type"),
                    apr_table_get(f->r->headers_in, "Content-Encoding"),
                    &ctx->file);
            if (APR_SUCCESS != rv) {
                ap_remove_output_filter(f);
                return ap_pass_brigade(f->next, bb);
            }

        }

        /* read the bucket in, pack it into the buffer */
        if (APR_SUCCESS == (rv = apr_bucket_read(e, &data, &size,
                                                 APR_BLOCK_READ))) {

            if (!skip) {
                apr_size_t written;
                rv = apr_file_write_full(ctx->file, data, size, &written);
                if (APR_SUCCESS != rv) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, f->r,
                            "Could not write to request file, scrape incomplete");
                    skip = 1;
                }
            }

        } else {
            return rv;
        }

    }

    if (skip) {
        ap_remove_input_filter(f);
    }

    return APR_SUCCESS;
}

static void *create_scrape_config(apr_pool_t *p, char *dummy)
{
    scrape_conf *new = (scrape_conf *) apr_pcalloc(p, sizeof(scrape_conf));

    apr_temp_dir_get(&new->path, p); /* default path */

    return (void *) new;
}

static void *merge_scrape_config(apr_pool_t *p, void *basev, void *addv)
{
    scrape_conf *new = (scrape_conf *) apr_pcalloc(p, sizeof(scrape_conf));
    scrape_conf *add = (scrape_conf *) addv;
    scrape_conf *base = (scrape_conf *) basev;

    new->path = (add->path_set == 0) ? base->path : add->path;
    new->path_set = add->path_set || base->path_set;

    return new;
}

static const char *set_scrape_path(cmd_parms *cmd, void *dconf, const char *arg)
{
    scrape_conf *conf = dconf;

    conf->path = arg;
    conf->path_set = 1;

    return NULL;
}

static const command_rec scrape_cmds[] = { AP_INIT_TAKE1("ScrapePath",
        set_scrape_path, NULL, RSRC_CONF | ACCESS_CONF,
        "Path to which scrapes are saved."), { NULL } };

static void register_hooks(apr_pool_t *p)
{
    ap_register_output_filter(scrapeFilterName, scrape_out_filter, NULL,
            AP_FTYPE_RESOURCE);
    ap_register_input_filter(scrapeFilterName, scrape_in_filter, NULL,
            AP_FTYPE_RESOURCE);
}

AP_DECLARE_MODULE(scrape) = {
    STANDARD20_MODULE_STUFF,
    create_scrape_config, /* create per-directory config structure */
    merge_scrape_config, /* merge per-directory config structures */
    NULL, /* create per-server config structure */
    NULL, /* merge per-server config structures */
    scrape_cmds, /* command apr_table_t */
    register_hooks /* register hooks */
};

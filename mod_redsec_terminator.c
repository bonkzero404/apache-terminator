#include "http_core.h"
#include "http_protocol.h"
#include "apr_strings.h"
#include "json-c/json.h"
#include "body_reader.h"
#include "json_reader.h"


static int mod_redsec_terminator_handler(request_rec *r) {
    if (apr_strnatcasecmp(r->handler, "mod_redsec_terminator")) {
        return DECLINED;
    }

    const char *content_type = apr_table_get(r->headers_in, "Content-Type");

    if (content_type) {
        r->content_type = apr_pstrdup(r->pool, content_type);
    } else {
        r->content_type = "text/html";
    }

    ap_rprintf(r, "Query Parameters:\n");
    if (r->args) {
        ap_rprintf(r, "%s\n", r->args);
    } else {
        ap_rprintf(r, "No query parameters.\n");
    }

    // Print request body
    ap_rputs("\nTes Request Body:\n", r);
    if (r->method_number == M_POST || r->method_number == M_PUT) {
        keyValuePair *formData;
        if (apr_strnatcasecmp(r->content_type, "application/json") == 0) {
            formData = readJson(r);
        } else {
            formData = readBody(r);
        }
        if (formData) {
            int i;
            for (i = 0; &formData[i]; i++) {
                if (formData[i].key && formData[i].value) {
                    ap_rprintf(r, "%s = %s\n", formData[i].key, formData[i].value);
                } else if (formData[i].key) {
                    ap_rprintf(r, "%s\n", formData[i].key);
                } else if (formData[i].value) {
                    ap_rprintf(r, "= %s\n", formData[i].value);
                } else {
                    break;
                }
            }
        }
    } else {
        ap_rputs("Method is not POST or PUT.\n", r);
    }

    return OK;
}

static void mod_redsec_terminator_register_hooks(apr_pool_t *p) {
    ap_hook_handler(mod_redsec_terminator_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA mod_redsec_terminator_module = {
    STANDARD20_MODULE_STUFF,
    NULL,            /* Per-directory configuration handler */
    NULL,            /* Merge handler for per-directory configurations */
    NULL,            /* Per-server configuration handler */
    NULL,            /* Merge handler for per-server configurations */
    NULL,            /* Any directives we may have for httpd */
    mod_redsec_terminator_register_hooks   /* register hooks */
};

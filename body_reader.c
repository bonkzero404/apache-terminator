#include "body_reader.h"
#include "http_log.h"


keyValuePair *readBody(request_rec *r)
{
    apr_array_header_t *pairs = NULL;
    apr_off_t len;
    apr_size_t size;
    int res;
    int i = 0;
    char *buffer;
    keyValuePair *kvp;

    res = ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN);
    if (res != OK || !pairs)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Failed to parse form data or no data present");
        return NULL; /* Return NULL if we failed or if there is no POST data */
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Form data parsed successfully");
    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Number of pairs: %d", pairs->nelts);

    kvp = apr_pcalloc(r->pool, sizeof(keyValuePair) * (pairs->nelts + 1));


    while (!apr_is_empty_array(pairs))
    {
        ap_form_pair_t *pair = (ap_form_pair_t *)apr_array_pop(pairs);
        apr_brigade_length(pair->value, 1, &len);
        size = (apr_size_t)len;
        buffer = apr_palloc(r->pool, size + 1);
        apr_brigade_flatten(pair->value, buffer, &size);
        buffer[len] = 0;
        kvp[i].key = apr_pstrdup(r->pool, pair->name);
        kvp[i].value = buffer;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Read key-value pair: %s = %s", kvp[i].key, kvp[i].value);
        i++;
    }
    return kvp;
}

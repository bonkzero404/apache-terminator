#include "json_reader.h"

keyValuePair *readJson(request_rec *r)
{
    apr_off_t size;
    const char *buffer;

    keyValuePair *kvp;

    if (util_read(r, &buffer, &size) == OK)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "buffer : %s\n", buffer);
        struct json_object *json_obj = json_tokener_parse(buffer);
        if (!json_obj)
        {
            return NULL;
        }

        kvp = apr_pcalloc(r->pool, sizeof(keyValuePair) * (json_object_object_length(json_obj) + 1));

        if (kvp == NULL) {
            return NULL;  // Handle memory allocation failure
        }

		// json_obj to string
		const char *json_str = json_object_to_json_string(json_obj);
		kvp[0].key = strdup("json");
		kvp[0].value = strdup(json_str);

        return kvp;
    }

    return NULL;
}

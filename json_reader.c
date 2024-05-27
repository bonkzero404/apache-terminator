#include "json_reader.h"

keyValuePair *readJson(request_rec *r) {
    apr_off_t   size;
    const char  *buffer;

    keyValuePair *kvp;

    if(util_read(r, &buffer, &size) == OK) {

        struct json_object *json_obj = json_tokener_parse(buffer);
        if (!json_obj) {
            return NULL;
        }

        kvp = apr_pcalloc(r->pool, sizeof(keyValuePair) * (json_object_object_length(json_obj) + 1));

        int i = 0;
        json_object_object_foreach(json_obj, key, val) {
            kvp[i].key = strdup(key);
            kvp[i].value = strdup(json_object_get_string(val));
            i++;
        }

        json_object_put(json_obj);

        return kvp;
    }

    return NULL;
}

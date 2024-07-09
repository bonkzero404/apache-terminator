
#include "form_reader.h"

char *trim_newline(char *str)
{
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == '\r' || *end == '\n'))
    {
        *end = '\0';
        end--;
    }
    return str;
}

keyValuePair *parse_multipart_form_data(request_rec *r)
{
    int rc;

    const char *content_type = apr_table_get(r->headers_in, "Content-Type");

    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK)
    {
        return NULL;
    }

    const char *boundary = strstr(content_type, "boundary=");
    if (!boundary)
    {
        return NULL;
    }

    boundary += strlen("boundary=");
    char *boundary_str = apr_pstrdup(r->pool, boundary);
    char *end_boundary_str = apr_pstrcat(r->pool, "--", boundary_str, "--", NULL);

    keyValuePair *kvp = NULL;
    int kvp_count = 0;

    if (ap_should_client_block(r))
    {
        char argsbuffer[HUGE_STRING_LEN];
        int len_read;
        apr_array_header_t *pairs = apr_array_make(r->pool, 10, sizeof(keyValuePair));

        while ((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0)
        {
            char *part_start = argsbuffer;
            while ((part_start = strstr(part_start, boundary_str)))
            {

                part_start += strlen(boundary_str);

                if (*part_start == '-' && *(part_start + 1) == '-')
                {
                    break; // End of multipart data
                }

                part_start += 2; // Skip the boundary line break

                char *part_end = strstr(part_start, boundary_str);

                if (!part_end)
                {
                    part_end = argsbuffer + len_read;
                }
                else
                {
                    part_end -= 2; // Remove the trailing line break before boundary
                }

                // *part_end = '\0';

                char *header_end = strstr(part_start, "\r\n\r\n");

                if (header_end)
                {
                    *header_end = '\0';
                    char *body_start = header_end + 4;

                    if (body_start >= part_end)
                    {
                        break;
                    }

                    char *content_disposition = strstr(part_start, "Content-Disposition:");
                    char *content_type_start = strstr(part_start, "Content-Type:");
                    if (content_disposition)
                    {
                        char *name_start = strstr(content_disposition, "name=\"");
                        char *namefile = strstr(content_disposition, "filename=\"");

                        if (name_start)
                        {

                            name_start += strlen("name=\"");

                            char *name_end = strstr(name_start, "\"");


                            if (content_type_start != NULL && namefile != NULL)
                            {

                                namefile += strlen("filename=\"");
                                char *file_end = strstr(namefile, "\"");

                                if (file_end)
                                {
                                    *file_end = '\0';
                                    *name_end = '\0';
                                    char *key = apr_pstrdup(r->pool, name_start);
                                    char *value = apr_pstrdup(r->pool, namefile);

                                    value = trim_newline(value);

                                    keyValuePair *pair = (keyValuePair *)apr_array_push(pairs);
                                    pair->key = key;
                                    pair->value = value;

                                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Read key-value pair: %s = %s", key, value);
                                }
                            }
                            else
                            {


                                if (name_end)
                                {
                                    *name_end = '\0';
                                    char *key = apr_pstrdup(r->pool, name_start);

                                    char *value = apr_pstrndup(r->pool, body_start, part_end - body_start);
                                    value = trim_newline(value);

                                    keyValuePair *pair = (keyValuePair *)apr_array_push(pairs);
                                    pair->key = key;
                                    pair->value = value;

                                    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Read key-value pair: %s = %s", key, value);
                                }
                            }
                        }
                    }

                    // if (content_type_start)
                    // {
                    //     content_type_start += strlen("Content-Type:");
                    //     while (*content_type_start == ' ')
                    //     {
                    //         content_type_start++;
                    //     }
                    //     char *content_type_end = strstr(content_type_start, "\r\n");

                    //     ap_rprintf(r, "test: %s\n", content_type_end);

                    //     if (content_type_end)
                    //     {
                    //         *content_type_end = '\0';
                    //         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Content-Type: %s", content_type_start);
                    //     }
                    // }
                }

                part_start = part_end;
            }
        }

        // Output pairs to the response
        kvp = apr_pcalloc(r->pool, sizeof(keyValuePair) * (pairs->nelts + 1));
        for (int i = 0; i < pairs->nelts; i++)
        {
            keyValuePair *pair = &((keyValuePair *)pairs->elts)[i];
            kvp[i].key = pair->key;
            kvp[i].value = pair->value;
        }
    }
    return kvp;
}

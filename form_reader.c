
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

static int upload_file(const char *filepath, const char *content, size_t content_length)
{
    FILE *file = fopen(filepath, "wb");
    if (!file)
    {
        return -1; // File open error
    }
    fwrite(content, sizeof(char), content_length, file);
    fclose(file);

    if (chmod(filepath, 0666) != 0)
    {
        return -1; // Gagal mengatur izin
    }

    return 0; // Success
}

keyValuePair *parse_multipart_form_data(request_rec *r, const char *path_temp, int clamav_status)
{

    apr_off_t size;
    const char *buffer;
    keyValuePair *kvp;

    if (util_read(r, &buffer, &size) == OK)
    {
        const char *boundary = strstr(r->content_type, "boundary=");
        if (!boundary)
        {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "No boundary found in Content-Type");
            return NULL;
        }
        boundary += 9; // Move past "boundary="
        
        const char *boundary_str = apr_pstrcat(r->pool, "--", boundary, NULL);
        
        kvp = apr_pcalloc(r->pool, sizeof(keyValuePair) * (size + 1));
        if (kvp == NULL)
        {
            return NULL; // Handle memory allocation failure
        }

        const char *part_start = strstr(buffer, boundary_str);
        int i = 0;
        while ((part_start = strstr(part_start, boundary_str)))
        {
            part_start += strlen(boundary_str);
            if (*part_start == '-' && *(part_start + 1) == '-')
            {
                break; // End of multipart data
            }

            part_start += 2; // Skip the boundary line break

            const char *part_end = strstr(part_start, boundary_str);
            if (!part_end)
            {
                part_end = buffer + size;
            }
            else
            {
                part_end -= 2; // Remove the trailing line break before boundary
            }

            const char *header_end = strstr(part_start, "\r\n\r\n");
            if (header_end)
            {
                char *header_end_modifiable = (char *)header_end;
                *header_end_modifiable = '\0';
                const char *body_start = header_end + 4;

                if (body_start >= part_end)
                {
                    break;
                }

                const char *content_disposition = strstr(part_start, "Content-Disposition:");
                const char *content_type_start = strstr(part_start, "Content-Type:");
                if (content_disposition)
                {
                    const char *name_start = strstr(content_disposition, "name=\"");
                    const char *namefile = strstr(content_disposition, "filename=\"");

                    if (name_start)
                    {
                        name_start += strlen("name=\"");
                        const char *name_end = strstr(name_start, "\"");

                        if (content_type_start != NULL && namefile != NULL)
                        {
                            namefile += strlen("filename=\"");
                            const char *file_end = strstr(namefile, "\"");

                            if (file_end)
                            {
                                char *file_end_modifiable = (char *)file_end;
                                *file_end_modifiable = '\0';
                                char *name_end_modifiable = (char *)name_end;
                                *name_end_modifiable = '\0';

                                char *key = apr_pstrdup(r->pool, name_start);
                                char *value = apr_pstrdup(r->pool, namefile);
                                value = trim_newline(value);

                                if (clamav_status == 1)
                                {
                                    char file_path[512];
                                    snprintf(file_path, sizeof(file_path), "%s/%s", path_temp, value);
                                    if (upload_file(file_path, body_start, part_end - body_start) == 0)
                                    {
                                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "File uploaded successfully: %s\n", file_path);
                                    }
                                    else
                                    {
                                        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to upload successfully: %s\n", file_path);
                                    }
                                }

                                kvp[i].key = key;
                                kvp[i].value = value;
                                kvp[i].type = strdup("file");
                            }
                        }
                        else
                        {
                            if (name_end)
                            {
                                char *name_end_modifiable = (char *)name_end;
                                *name_end_modifiable = '\0';
                                char *key = apr_pstrdup(r->pool, name_start);
                                char *value = apr_pstrndup(r->pool, body_start, part_end - body_start);
                                value = trim_newline(value);

                                kvp[i].key = key;
                                kvp[i].value = value;
                                kvp[i].type = strdup("text");
                            }
                        }
                    }
                }
            }

            part_start = part_end;
            i++;
        }

        kvp[i].key = NULL;
    }


    return kvp;
}
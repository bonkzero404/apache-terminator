#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "json-c/json.h"
#include "body_reader.h"
#include "json_reader.h"
#include "http_log.h"
#include "mod_sec.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
// #include "mod_security.h"

module AP_MODULE_DECLARE_DATA mod_redsec_terminator_module;

typedef struct
{
    const char *socket_url;
} mod_redsec_terminator_config;

char *trim_newline(char *str) {
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == '\r' || *end == '\n')) {
        *end = '\0';
        end--;
    }
    return str;
}


static keyValuePair *parse_multipart_form_data(request_rec *r)
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
                        if (name_start)
                        {
                            name_start += strlen("name=\"");
                            char *name_end = strstr(name_start, "\"");
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

                    if (content_type_start)
                    {
                        content_type_start += strlen("Content-Type:");
                        while (*content_type_start == ' ')
                        {
                            content_type_start++;
                        }
                        char *content_type_end = strstr(content_type_start, "\r\n");
                        if (content_type_end)
                        {
                            *content_type_end = '\0';
                            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Content-Type: %s", content_type_start);
                        }
                    }
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

static void *create_mod_redsec_terminator_config(apr_pool_t *p, char *dir)
{
    mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)apr_pcalloc(p, sizeof(mod_redsec_terminator_config));
    config->socket_url = NULL; // Initialize socket_url to NULL
    return (void *)config;
}

static const char *set_socket_url(cmd_parms *cmd, void *cfg, const char *arg)
{
    mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)cfg;
    config->socket_url = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static int send_to_tcp_socket(const char *url, const char *data)
{
    int sockfd, status;
    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char *hostname;
    char *port_str;
    char *url_copy = apr_pstrdup(apr_hook_global_pool, url);

    if (strncmp(url_copy, "http://", 7) == 0)
    {
        url_copy += 7;
    }
    else if (strncmp(url_copy, "https://", 8) == 0)
    {
        url_copy += 8;
    }

    hostname = strtok(url_copy, ":/");
    port_str = strtok(NULL, ":/");

    if (port_str == NULL)
    {
        port_str = "80";
    }

    if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: getaddrinfo error: %s", gai_strerror(status));
    }

    for (p = res; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error opening socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error connecting to socket");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to connect to socket");
    }

    freeaddrinfo(res);

    int bytes_sent = send(sockfd, data, strlen(data), 0);
    if (bytes_sent == -1)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error sending data");
        close(sockfd);
    }

    close(sockfd);
    return 0;
}

static int log_mod(request_rec *r)
{

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "data: %s", r->server->server_hostname);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "data log : %d", r->server->port);
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "request number : %d", r->method_number);
    return OK;
}

static int mod_redsec_terminator_handler(request_rec *r)
{

    const char *content_type = apr_table_get(r->headers_in, "Content-Type");

    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Content-Type found: %s", content_type);
    if (content_type)
    {
        r->content_type = apr_pstrdup(r->pool, content_type);
    }
    else
    {
        r->content_type = "text/html";
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Content-Type not found, defaulting to text/html");
    }

    if (apr_strnatcasecmp(r->handler, "mod_redsec_terminator"))
    {
        return DECLINED;
    }

    mod_redsec_terminator_config *config = ap_get_module_config(r->per_dir_config, &mod_redsec_terminator_module);
    if (!config || !config->socket_url)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Configuration not initialized properly");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    const char *url_socket = config->socket_url;

    json_object *json_obj = json_object_new_object();
    json_object *msc_obj = json_object_new_object();
    json_object *query_params_obj = json_object_new_object();
    json_object *body_obj = json_object_new_object();

    if (r->args)
    {

        char *query_params = apr_pstrdup(r->pool, r->args);
        char *param_name = strtok(query_params, "&?");

        while (param_name != NULL)
        {
            char *param_value = strchr(param_name, '=');
            if (param_value)
            {
                *param_value++ = '\0';

                json_object_object_add(query_params_obj, param_name, json_object_new_string(param_value));
            }
            else
            {
                json_object_object_add(query_params_obj, param_name, json_object_new_string(""));
            }
            param_name = strtok(NULL, "&?");
        }
    }
    else
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: No query parameters");
    }

    log_mod(r);

    if (r->method_number == M_POST || r->method_number == M_PUT || r->method_number == M_PATCH || r->method_number == M_DELETE || r->method_number == M_GET)
    {
        const char *prefixFormData = "multipart/form-data";
        keyValuePair *formData;
        if (apr_strnatcasecmp(r->content_type, "application/json") == 0)
        {
            formData = readJson(r);
        } else if (strncmp(r->content_type, prefixFormData, strlen(prefixFormData)) == 0)
        {
            formData = parse_multipart_form_data(r);
        }
        else
        {
            formData = readBody(r);
        }
        if (formData)
        {

            for (int i = 0; formData[i].key || formData[i].value; i++)
            {
                json_object_object_add(body_obj, formData[i].key ? formData[i].key : "", json_object_new_string(formData[i].value ? formData[i].value : ""));
            }
        }
    }
    else
    {
        ap_rprintf(r, "Method is empty %d\n", M_POST);
    }

    json_object_object_add(json_obj, "query_params", query_params_obj);
    json_object_object_add(json_obj, "body", body_obj);
    if (strncmp(r->protocol, "HTTP/1.1", 8) == 0)
    {
        json_object_object_add(json_obj, "protocol", json_object_new_string("http"));
    }
    else if (strncmp(r->protocol, "HTTP/2", 6) == 0)
    {
        json_object_object_add(json_obj, "protocol", json_object_new_string("https"));
    }
    json_object_object_add(json_obj, "host", json_object_new_string(r->hostname));
    json_object_object_add(json_obj, "uri", json_object_new_string(r->uri));
    json_object_object_add(json_obj, "method", json_object_new_string(r->method));
    json_object_object_add(json_obj, "remote_ip", json_object_new_string(r->useragent_ip));
    json_object_object_add(json_obj, "user_agent", json_object_new_string(apr_table_get(r->headers_in, "User-Agent")));

    // MOD

    ModSecValuePair *modSecVal;

    modSecVal = mod_sec_handler(r, body_obj);

    if (modSecVal != NULL)
    {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Processing ModSecurity Rules %s", modSecVal->message);

        if (modSecVal->status != 200)
        {

            ap_rprintf(r, "STATUS: %d\n", modSecVal->status);
        }

        json_object_object_add(json_obj, "msc_report", msc_obj);

        json_object_object_add(msc_obj, "status_msc", json_object_new_int(modSecVal->status));

        if (modSecVal->message != NULL)
        {
            json_object_object_add(msc_obj, "message_msc", json_object_new_string(modSecVal->message));
            ap_rprintf(r, "MESSAGE: %s\n", modSecVal->message);

            return HTTP_FORBIDDEN;
        }

        r->status = modSecVal->status;

        free((char *)modSecVal->message);
        free(modSecVal);
    }

    const char *json_str = json_object_to_json_string(json_obj);


    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Log Header Content Type: %s", apr_table_get(r->headers_in, "User-Agent"));

    log_mod(r);
    send_to_tcp_socket(url_socket, json_str);

    // json_object_put(json_obj);
    // json_object_put(query_params_obj);
    // json_object_put(body_obj);

    return DECLINED;
}

static void mod_redsec_terminator_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(mod_redsec_terminator_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec mod_redsec_terminator_cmds[] = {
    AP_INIT_TAKE1("RedSecTerminatorURLSocket", set_socket_url, NULL, RSRC_CONF,
                  "Specify the custom socket URL for data transmission"),
    {NULL}};

module AP_MODULE_DECLARE_DATA mod_redsec_terminator_module = {
    STANDARD20_MODULE_STUFF,
    create_mod_redsec_terminator_config,
    NULL,
    NULL,
    NULL,
    mod_redsec_terminator_cmds,
    mod_redsec_terminator_register_hooks};

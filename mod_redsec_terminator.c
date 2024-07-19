#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "json-c/json.h"
#include "body_reader.h"
#include "json_reader.h"
#include "form_reader.h"
#include "http_log.h"
#include "mod_sec.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <clamav.h>
#include "clamav_sec.h"

module AP_MODULE_DECLARE_DATA mod_redsec_terminator_module;

typedef struct
{
    const char *socket_url;
    const char *path_temporary;
    int clamav_enabled;
    struct cl_engine *engine;
} mod_redsec_terminator_config;

static void *create_mod_redsec_terminator_config(apr_pool_t *p, char *dir)
{
    mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)apr_pcalloc(p, sizeof(mod_redsec_terminator_config));
    config->socket_url = NULL; // Initialize socket_url to NULL
    config->path_temporary = NULL;
    config->clamav_enabled = 0;
    config->engine = NULL;
    return (void *)config;
}

static int initialize_clamav(mod_redsec_terminator_config *config)
{
    // Initialize ClamAV engine
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "failed load %d\n", config->clamav_enabled);

    config->engine = cl_engine_new();
    if (!config->engine)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to create ClamAV engine");
    }

    // Initialize ClamAV
    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to initialize ClamAV");
        cl_engine_free(config->engine);
    }

    // Load virus database
    const char *dbclamav = "/var/lib/clamav";
    if (cl_load(dbclamav, config->engine, NULL, CL_DB_STDOPT) != CL_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to load virus database from %s", dbclamav);
        cl_engine_free(config->engine);
    }

    // Compile engine after loading database
    if (cl_engine_compile(config->engine) != CL_SUCCESS)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to compile ClamAV engine");
        cl_engine_free(config->engine);
    }
    return 0;
}

static const char *set_socket_url(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "config set %s", arg);

    mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)cfg;
    config->socket_url = apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *set_clamav_engine(cmd_parms *cmd, void *cfg, const char *arg)
{
    mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)cfg;

    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "config set %s", arg);

    if (strcasecmp(arg, "ON") == 0)
    {

        config->clamav_enabled = 1;
        initialize_clamav(config);
    }
    else if (strcasecmp(arg, "OFF") == 0)
    {
        config->clamav_enabled = 0;
    }

    return NULL;
}

static const char *set_path_temporary(cmd_parms *cmd, void *cfg, const char *arg)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "config set %s", arg);

    mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)cfg;
    config->path_temporary = apr_pstrdup(cmd->pool, arg);
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



static int modSecHandle(request_rec *r)
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
    json_object *upload_filter = json_object_new_array();
    ModSecValuePair *modSecVal = NULL;

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

    if (r->method_number == M_POST || r->method_number == M_PUT || r->method_number == M_PATCH || r->method_number == M_DELETE || r->method_number == M_GET)
    {
        const char *prefixFormData = "multipart/form-data";
        keyValuePair *formData;
        if (apr_strnatcasecmp(r->content_type, "application/json") == 0)
        {
            formData = readJson(r);
        }
        else if (strncmp(r->content_type, prefixFormData, strlen(prefixFormData)) == 0)
        {
            formData = parse_multipart_form_data(r, config->path_temporary, config->clamav_enabled);
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
                if (formData[i].type && apr_strnatcasecmp(formData[i].type, "file") == 0 && config->clamav_enabled == 1)
                {
                    char file_path[512];
                    snprintf(file_path, sizeof(file_path), "%s/%s", config->path_temporary, formData[i].value);

                    modSecVal = clamav_handle(r, (const char *)file_path, formData[i].value, config->engine);

                    if (modSecVal != NULL)
                    {

                        json_object *status_message_obj = json_object_new_object();

                        json_object_object_add(status_message_obj, "status", json_object_new_int64(modSecVal->status ? modSecVal->status : 200));
                        json_object_object_add(status_message_obj, "message", json_object_new_string(modSecVal->message ? modSecVal->message : ""));

                        json_object_array_add(upload_filter, status_message_obj);
                    }
                }
            }
        }
    }
    else
    {
        ap_rprintf(r, "Method is empty %d\n", M_POST);
    }

    if (json_obj != NULL)
    {
        json_object_object_add(json_obj, "query_params", query_params_obj);
        json_object_object_add(json_obj, "body", body_obj);
        json_object_object_add(json_obj, "upload_filter", upload_filter);
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
    }

    const char *json_str = json_object_to_json_string(json_obj);
    // MOD

    if (modSecVal == NULL)
    {
        modSecVal = mod_sec_handler(r, body_obj, url_socket);
        // free(modSecVal);
    }

    if (modSecVal != NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Processing ModSecurity Rules %ld", json_object_array_length(upload_filter));

        for (size_t i = 0; i < json_object_array_length(upload_filter); i++)
        {
            // Ambil objek pada index ke-i dari array
            json_object *status_message_obj = json_object_array_get_idx(upload_filter, i);

            // Ambil nilai status dan pesan dari objek
            json_object *status_obj;
            json_object *message_obj;

            if (json_object_object_get_ex(status_message_obj, "status", &status_obj) &&
                json_object_object_get_ex(status_message_obj, "message", &message_obj))
            {

                int status = json_object_get_int(status_obj);
                const char *message = json_object_get_string(message_obj);

                if (status != 200 && message != NULL)
                {
                    json_object_object_add(msc_obj, "status_msc", json_object_new_int(status));
                    json_object_object_add(msc_obj, "message_msc", json_object_new_string(message));

                    json_object_object_add(json_obj, "msc_report", msc_obj);

                    const char *json_filter = json_object_to_json_string(json_obj);

                    send_to_tcp_socket(url_socket, json_filter);

                    free(modSecVal);

                    return HTTP_FORBIDDEN;
                }
            }
        }

        if (modSecVal->status != 200 && modSecVal->message != NULL)
        {

            ap_rprintf(r, "STATUS: %d\n", modSecVal->status);

            json_object_object_add(msc_obj, "status_msc", json_object_new_int(modSecVal->status));

            json_object_object_add(msc_obj, "message_msc", json_object_new_string(modSecVal->message));
            json_object_object_add(json_obj, "msc_report", msc_obj);
            ap_rprintf(r, "MESSAGE: %s\n", modSecVal->message);

            const char *json_string = json_object_to_json_string(json_obj);

            send_to_tcp_socket(url_socket, json_string);

            free(modSecVal);

            return HTTP_FORBIDDEN;
        }
    }

    ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Log Header Content Type: %s", apr_table_get(r->headers_in, "User-Agent"));

    send_to_tcp_socket(url_socket, json_str);

    // json_object_put(json_obj);
    // json_object_put(query_params_obj);
    // json_object_put(body_obj);

    free(modSecVal);

    return DECLINED;
}

static void mod_redsec_terminator_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(mod_redsec_terminator_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec mod_redsec_terminator_cmds[] = {
    AP_INIT_TAKE1("RedSecTerminatorURLSocket", set_socket_url, NULL, RSRC_CONF,
                  "Specify the custom socket URL for data transmission"),
    AP_INIT_TAKE1("RedSecTerminatorClamAVengine", set_clamav_engine, NULL, RSRC_CONF,
                  "Enable or disable ClamAV engine (ON/OFF)"),
    AP_INIT_TAKE1("TemporaryFileScan", set_path_temporary, NULL, RSRC_CONF,
                  "Enable or disable ClamAV engine (ON/OFF)"),
    {NULL}};

module AP_MODULE_DECLARE_DATA mod_redsec_terminator_module = {
    STANDARD20_MODULE_STUFF,
    create_mod_redsec_terminator_config,
    NULL,
    NULL,
    NULL,
    mod_redsec_terminator_cmds,
    mod_redsec_terminator_register_hooks};

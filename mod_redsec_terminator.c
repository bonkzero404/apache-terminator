#include "http_core.h"
#include "http_protocol.h"
#include "apr_strings.h"
#include "json-c/json.h"
#include "body_reader.h"
#include "json_reader.h"
#include "http_log.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

static int send_to_tcp_socket(const char *url, const char *data) {
    int sockfd, status;
    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Use IPv4 or IPv6, whichever is available
    hints.ai_socktype = SOCK_STREAM;

    // Parse URL to get host and port
    char *hostname;
    char *port_str;
    char *url_copy = apr_pstrdup(apr_hook_global_pool, url);

    if (strncmp(url_copy, "http://", 7) == 0) {
        url_copy += 7;
    } else if (strncmp(url_copy, "https://", 8) == 0) {
        url_copy += 8;
    }

    hostname = strtok(url_copy, ":/");
    port_str = strtok(NULL, ":/");

    if (port_str == NULL) {
        port_str = "80";
    }

    if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: getaddrinfo error: %s", gai_strerror(status));
        return -1;
    }

    // Loop over all the results and connect to the first we can
    for (p = res; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error opening socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error connecting to socket");
            continue;
        }

        break; // Connected successfully
    }

    if (p == NULL) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to connect to socket");
        return -1;
    }

    freeaddrinfo(res); // All done with this structure

    // Now send data to the socket
    int bytes_sent = send(sockfd, data, strlen(data), 0);
    if (bytes_sent == -1) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error sending data");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}

static int mod_redsec_terminator_handler(request_rec *r) {
    if (apr_strnatcasecmp(r->handler, "mod_redsec_terminator")) {
        return DECLINED;
    }

    const char *content_type = apr_table_get(r->headers_in, "Content-Type");

    if (content_type) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Content-Type: %s", content_type);
        r->content_type = apr_pstrdup(r->pool, content_type);
    } else {
        r->content_type = "text/html";
    }

    const char *url_socket = "http://localhost:8585"; // Destination URL for socket

    json_object *json_obj = json_object_new_object();
    json_object *query_params_obj = json_object_new_object();
    json_object *body_obj = json_object_new_object();

    // Parse query parameters
    if (r->args) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Query parameters: %s", r->args);

        char *query_params = apr_pstrdup(r->pool, r->args);
        char *param_name = strtok(query_params, "&?");

        while (param_name != NULL) {
            char *param_value = strchr(param_name, '=');
            if (param_value) {
                *param_value++ = '\0';
                json_object_object_add(query_params_obj, param_name, json_object_new_string(param_value));
            } else {
                json_object_object_add(query_params_obj, param_name, json_object_new_string(""));
            }
            param_name = strtok(NULL, "&?");
        }
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: No query parameters");
    }

    // Process request body
    if (r->method_number == M_POST || r->method_number == M_PUT || r->method_number == M_PATCH || r->method_number == M_DELETE || r->method_number == M_GET) {
        keyValuePair *formData;
        if (apr_strnatcasecmp(r->content_type, "application/json") == 0) {
            formData = readJson(r);
        } else {
            formData = readBody(r);
        }
        if (formData) {
            for (int i = 0; formData[i].key || formData[i].value; i++) {
                json_object_object_add(body_obj, formData[i].key ? formData[i].key : "", json_object_new_string(formData[i].value ? formData[i].value : ""));
            }
        }
    }

    // Add query_params, body, and url to the json_obj
    json_object_object_add(json_obj, "query_params", query_params_obj);
    json_object_object_add(json_obj, "body", body_obj);
	if (strncmp(r->protocol, "HTTP/1.1", 8) == 0) {
		json_object_object_add(json_obj, "protocol", json_object_new_string("http"));
	} else if (strncmp(r->protocol, "HTTP/2", 6) == 0) {
		json_object_object_add(json_obj, "protocol", json_object_new_string("https"));
	}
    json_object_object_add(json_obj, "host", json_object_new_string(r->hostname));
	json_object_object_add(json_obj, "uri", json_object_new_string(r->uri));
	json_object_object_add(json_obj, "method", json_object_new_string(r->method));
	json_object_object_add(json_obj, "remote_ip", json_object_new_string(r->useragent_ip));

    const char *json_str = json_object_to_json_string(json_obj);

    // Send data to TCP socket
    send_to_tcp_socket(url_socket, json_str);

    // Cleanup JSON objects
    json_object_put(json_obj);
    json_object_put(query_params_obj);
    json_object_put(body_obj);

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

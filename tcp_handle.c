#include "tcp_handle.h"

char *handle_tcp_receipt(const char *url)
{
    int sockfd, status;
    struct addrinfo hints, *res, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char *hostname;
    char *port_str;
    char *url_copy = strdup(url); // Use strdup to allocate memory and copy the URL

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
        return NULL;
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
        freeaddrinfo(res);
        return NULL;
    }

    freeaddrinfo(res);

    // Handle receiving data
    char recv_buffer[1024];
    char *data = NULL;
    int total_size = 0;
    int bytes_recv;

    while ((bytes_recv = recv(sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0)) > 0)
    {
        // Reallocate memory to hold received data
        data = realloc(data, total_size + bytes_recv + 1);
        if (data == NULL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Memory allocation error");
            close(sockfd);
            return NULL;
        }

        // Copy received data to the end of the buffer
        memcpy(data + total_size, recv_buffer, bytes_recv);
        total_size += bytes_recv;
        data[total_size] = '\0'; // Null-terminate the string

        // Break if there's no more data
        if (bytes_recv < sizeof(recv_buffer) - 1)
        {
            break;
        }
    }

    if (bytes_recv == -1)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error receiving data");
        free(data);
        close(sockfd);
        return NULL;
    }

    close(sockfd);
    return data;
}

TCPValueConfig *handle_config_receipt(const char *urls)
{
    char *rules_accept = handle_tcp_receipt(urls);
    TCPValueConfig *config = NULL;

    if (rules_accept != NULL)
    {
        json_object *parsed_json;
        json_object *pathDir;
        json_object *filenameRule;
        json_object *forbiddenPage;
        json_object *clamavStatus;
        json_object *clamavDbDirectory;

        // Parse the JSON string
        parsed_json = json_tokener_parse(rules_accept);
        free(rules_accept); // Free the received data

        if (parsed_json == NULL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to parse JSON");
            return NULL;
        }

        config = (TCPValueConfig *)malloc(sizeof(TCPValueConfig));
        if (config == NULL)
        {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Memory allocation error for TCPValueConfig");
            json_object_put(parsed_json);
            return NULL;
        }

        // Initialize config with default values
        config->clamav_DB = NULL;
        config->clamav_status = 0;
        config->rules_filename = NULL;
        config->custom_mod_sec_page = NULL;
        config->main_directory = NULL;

        // Setting config with tcp
        if (json_object_object_get_ex(parsed_json, "clamav_status", &clamavStatus))
        {
            const char *status_str = json_object_get_string(clamavStatus);

            if (strcasecmp(status_str, "ON") == 0)
            {
                config->clamav_status = 1;
            }
            else
            {
                config->clamav_status = 0;
            }
        }

        if (config->clamav_status == 1 && json_object_object_get_ex(parsed_json, "clamav_db", &clamavDbDirectory))
        {
            const char *path_db = json_object_get_string(clamavDbDirectory);
            config->clamav_DB = strdup(path_db);
        }

        if (json_object_object_get_ex(parsed_json, "main_directory", &pathDir))
        {
            const char *mainDir = json_object_get_string(pathDir);
            config->main_directory = strdup(mainDir);

            if (json_object_object_get_ex(parsed_json, "rules_filename", &filenameRule))
            {
                const char *rule_file = json_object_get_string(filenameRule);

				char rule_path[512];
                snprintf(rule_path, sizeof(rule_path), "%s/%s", config->main_directory, rule_file);
                config->rules_filename = strdup(rule_path);
            }

            if (json_object_object_get_ex(parsed_json, "custom_mod_sec_page", &forbiddenPage))
            {

                const char *forbiddenFile = json_object_get_string(forbiddenPage);
				char forbidden_path[512];
                snprintf(forbidden_path, sizeof(forbidden_path), "%s/%s", config->main_directory, forbiddenFile);
                config->custom_mod_sec_page = strdup(forbidden_path);
            }
        }

        json_object_put(parsed_json);
    }

    return config;
}

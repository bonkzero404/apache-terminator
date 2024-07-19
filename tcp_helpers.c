#include "tcp_helpers.h"
#define BUFFER_SIZE 1024

char* receive_from_tcp_socket(const char *url) {
    char buffer[BUFFER_SIZE];
    char *data = NULL;
    size_t total_length = 0;
    size_t buffer_size = BUFFER_SIZE;

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
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error opening tcp not connedted sockfd");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error connecting tcp not connected");
            continue;
        }

        break;
    }

    if (p == NULL)
    {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to connect tcp p not found");
    }

    freeaddrinfo(res);


    // Receive data from the socket
    ssize_t bytes_received;

    bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received < 0) {
        perror("recv");
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to connect tcp  %ld", bytes_received);
    } else {
        buffer[bytes_received] = '\0';
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to connect tcp %ld", bytes_received);
    }

    close(sockfd);
    return data;
}

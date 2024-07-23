#include "tcp_handle.h"

char *handle_tcp_receipt(request_rec *r, const char *url)
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

	return apr_pstrdup(r->pool, data);

}




#ifndef TCP_HELPERS_H
#define TCP_HELPERS_H

#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "json-c/json.h"
#include "http_log.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>


char *receive_from_tcp_socket(const char *url);

#endif // TCP_HELPERS_H

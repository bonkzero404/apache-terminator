#ifndef TCP_HANDLE_H
#define TCP_HANDLE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <httpd.h>
#include <http_log.h>
#include <apr_strings.h>
#include "json-c/json.h"
#include "util.h"


char *handle_tcp_receipt(const char *urls);

TCPValueConfig *handle_config_receipt(const char *urls);

#endif // TCP_HANDLE_H

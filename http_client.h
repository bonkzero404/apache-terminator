#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stdlib.h>
#include <string.h>
#include <httpd.h>
#include <http_log.h>
#include <curl/curl.h>

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp);
int http_get(const char *url, const struct curl_slist *headers, char **response);

#endif // HTTP_CLIENT_H

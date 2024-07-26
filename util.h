#ifndef UTIL_H
#define UTIL_H

#include "http_protocol.h"

typedef struct {
    const char *key;
    const char *value;
    const char *type;
} keyValuePair;

typedef struct {
    int status;
    const char *message;
} ModSecValuePair;

typedef struct {
    const char *clamav_DB;
	int clamav_status;
    const char *rules_filename;
    const char *custom_mod_sec_page;
    const char *main_directory;
} TCPValueConfig;

int util_read(request_rec *r, const char **rbuf, apr_off_t *size);

#endif // UTIL_H

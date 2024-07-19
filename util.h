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

int util_read(request_rec *r, const char **rbuf, apr_off_t *size);

#endif // UTIL_H

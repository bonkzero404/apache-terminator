#ifndef CLAMAV_SEC_H
#define CLAMAV_SEC_H

#include "util.h"
#include "http_log.h"
#include <apr_strings.h>
#include <string.h>
#include <clamav.h>

ModSecValuePair *clamav_handle(request_rec *r, const char *pathfile, struct cl_engine *engine);

#endif // CLAMAV_SEC_H

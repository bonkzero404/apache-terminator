#ifndef JSON_READER_H
#define JSON_READER_H

#include "httpd.h"
#include "util.h"
#include "http_log.h"
#include "json-c/json.h"

keyValuePair *readJson(request_rec *r);

#endif // JSON_READER_H

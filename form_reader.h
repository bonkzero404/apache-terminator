#ifndef FORM_READER_H
#define FORM_READER_H

#include "httpd.h"
#include "util.h"
#include "http_log.h"
#include <apr_strings.h>
#include <string.h>
#include "json-c/json.h"

keyValuePair *parse_multipart_form_data(request_rec *r);

#endif // FORM_READER_H

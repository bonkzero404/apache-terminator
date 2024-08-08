#ifndef BODY_READER_H
#define BODY_READER_H

#include "httpd.h"
#include "util.h"
#include "apr_strings.h"


keyValuePair *readBody(request_rec *r);

#endif // BODY_READER_H

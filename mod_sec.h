#ifndef MOD_SEC_H
#define MOD_SEC_H

#include "httpd.h"
#include "util.h"
#include "apr_strings.h"
#include "json-c/json.h"
#include "http_log.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/intervention.h"
#include "modsecurity/rules_set.h"

ModSecValuePair *mod_sec_handler(request_rec *r);

#endif // MOD_SEC_H

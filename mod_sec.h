#ifndef MOD_SEC_H
#define MOD_SEC_H

#include "httpd.h"
#include "util.h"
#include "apr_strings.h"
#include "json-c/json.h"
#include "http_log.h"
#include "modsecurity/modsecurity.h"
#include "modsecurity/intervention.h"
#include "modsecurity/transaction.h"
#include "modsecurity/rules_set.h"
#include "tcp_handle.h"

ModSecValuePair *mod_sec_handler(request_rec *r, json_object *json_obj, const char *rules_path, const char *socket_url);

#endif // MOD_SEC_H

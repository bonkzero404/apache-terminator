#include "mod_sec.h"
#include "body_reader.h"

static ModSecValuePair *process_intervention(request_rec *r, Transaction *trans)
{
    ModSecValuePair *msvp = malloc(sizeof(ModSecValuePair)); // Allocate memory for ModSecValuePair
    if (!msvp)
    {
        fprintf(stderr, "Failed to allocate memory for ModSecValuePair\n");
        return NULL;
    }
    msvp->message = NULL;

    ModSecurityIntervention it;
    it.status = 200;
    it.url = NULL;
    it.log = NULL;
    it.disruptive = 0;

    msc_intervention(trans, &it);

    if (it.log != NULL)
    {
        // ap_rprintf(r, "Detected message: %s\n", it.log);

        // Example parsing to extract specific message
        const char *xssMsg = "msg \"";
        const char *msgStart = strstr(it.log, xssMsg);
        if (msgStart)
        {
            msgStart += strlen(xssMsg);
            const char *msgEnd = strchr(msgStart, '"');
            if (msgEnd)
            {
                char *msg = malloc(msgEnd - msgStart + 1); // Allocate memory for message
                if (msg)
                {
                    strncpy(msg, msgStart, msgEnd - msgStart);
                    msg[msgEnd - msgStart] = '\0';
                    printf("Detected message: %s\n", msg);

                    msvp->message = msg;
                }
                else
                {
                    fprintf(stderr, "Failed to allocate memory for message\n");
                }
            }
        }
        free(it.log);
    }
    if (it.url != NULL)
    {
        free(it.url);
    }

    msvp->status = it.status;

    return msvp;
}

void add_request_headers_to_transaction(Transaction *transaction, request_rec *r)
{
    const apr_array_header_t *arr = apr_table_elts(r->headers_in);
    const apr_table_entry_t *elts = (const apr_table_entry_t *)arr->elts;

    const char *prefixFormData = "multipart/form-data";

    for (int i = 0; i < arr->nelts; i++)
    {
        if (strncmp(elts[i].val, prefixFormData, strlen(prefixFormData)) == 0)
        {
            msc_add_request_header(transaction, "Content-Type", "application/x-www-form-urlencoded");
        }
        else
        {

            msc_add_request_header(transaction, elts[i].key, elts[i].val);
        }
    }
}

void add_request_body(Transaction *transaction, json_object *json_obj)
{
    const char *body = json_object_to_json_string(json_obj);

    msc_append_request_body(transaction, body, strlen(body));
}

ModSecValuePair *mod_sec_handler(request_rec *r, json_object *json_obj)
{
    int ret;
    const char *error = NULL;
    ModSecurity *modsec;
    Transaction *transaction = NULL;
    RulesSet *rules;

    ModSecValuePair *msvp = NULL;


    // Initialize ModSecurity
    modsec = msc_init();
    if (!modsec)
    {

        fprintf(stderr, "Failed to initialize ModSecurity\n");
        return NULL;
    }

    // Set ModSecurity connector info
    msc_set_connector_info(modsec, "ModSecurity-test v0.0.1-alpha (Simple example on how to use ModSecurity API");

    // Create rules set
    rules = msc_create_rules_set();
    if (!rules)
    {
        fprintf(stderr, "Failed to create rules set\n");
        msc_cleanup(modsec);
        return NULL;
    }

    // Load local rules file
    ret = msc_rules_add_file(rules, "/Users/janitrasatria/Development/mod_redsec_terminator/basic_rules.conf", &error);
    if (ret < 0)
    {
        msc_cleanup(modsec);
        fprintf(stderr, "Failed to load local rules file: %s\n", error);
        return NULL;
    }
    // Create new transaction
    transaction = msc_new_transaction(modsec, rules, NULL);
    if (!transaction)
    {
        fprintf(stderr, "Failed to create new transaction\n");
        msc_cleanup(modsec);
        return NULL;
    }

	// Change current host and port
    msc_process_connection(transaction, r->useragent_ip, r->server->port, r->server->server_hostname, r->server->port);
    msc_process_uri(transaction, r->unparsed_uri, r->method, "HTTP/1.1");
    add_request_headers_to_transaction(transaction, r);

    // ap_rprintf(r, "asede %d\n", json_object_object_length(json_obj));

    if (json_object_object_length(json_obj) != 0)
    {

        add_request_body(transaction, json_obj);
    }

    msc_process_request_headers(transaction);
    msc_process_request_body(transaction);
    msc_process_response_headers(transaction, 200, "HTTP 1.3");
    msc_process_response_body(transaction);
    msc_process_logging(transaction);

    // Retrieve intervention details
    msvp = process_intervention(r, transaction);

    // Cleanup
    // free(full_uri);
    msc_transaction_cleanup(transaction);
    msc_rules_cleanup(rules);
    msc_cleanup(modsec);

    return msvp;
}

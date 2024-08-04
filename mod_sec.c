#include "mod_sec.h"
#include "body_reader.h"

static ModSecValuePair *process_intervention(request_rec *r, Transaction *trans)
{
	ModSecValuePair *msvp = malloc(sizeof(ModSecValuePair)); // Allocate memory for ModSecValuePair
	if (!msvp)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to allocate memory for ModSecValuePair");
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
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Detected message: %s", msg);

					msvp->message = msg;
				}
				else
				{
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to allocate memory for message");
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

ModSecValuePair *mod_sec_handler(request_rec *r, json_object *json_obj, const char *rules_path, const char *socket_url)
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
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to initialize ModSecurity");
		return NULL;
	}

	// Set ModSecurity connector info
	msc_set_connector_info(modsec, "ModSecurity-test v0.0.1-alpha (Simple example on how to use ModSecurity API");

	// Create rules set
	rules = msc_create_rules_set();
	if (!rules)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to create rules set");
		msc_cleanup(modsec);
		return NULL;
	}

	// Load local rules file

	if (rules_path) {

		ret = msc_rules_add_file(rules, rules_path, &error);
		if (ret < 0)
		{
			msc_cleanup(modsec);
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to get file : %s", error);
			return NULL;
		}
	}


	// Create new transaction
	transaction = msc_new_transaction(modsec, rules, NULL);
	if (!transaction)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Failed to create new transaction");
		msc_cleanup(modsec);
		return NULL;
	}

	// msc_process_connection(transaction, "127.0.0.1", 8282, "127.0.0.1", r->server->port);
	msc_process_connection(transaction, r->hostname, r->useragent_addr->port, r->server->server_hostname, r->server->port);
	msc_process_uri(transaction, r->unparsed_uri, r->method, "HTTP/1.1");
	add_request_headers_to_transaction(transaction, r);

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

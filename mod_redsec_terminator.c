#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "json-c/json.h"
#include "body_reader.h"
#include "json_reader.h"
#include "form_reader.h"
#include "http_log.h"
#include "mod_sec.h"
#include "seclang.h"
#include "http_client.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <clamav.h>
#include "clamav_sec.h"
#include "tcp_handle.h"

module AP_MODULE_DECLARE_DATA mod_redsec_terminator_module;

#define BUFFER_SIZE 102400

typedef struct {
	int config_remote;
	const char *rule_remote_url;
	const char *rule_remote_unicode;
	const char *sec_rule;
	const char *sec_rule_unicode;

	const char *config_path;
	const char *socket_url;
	const char *rule_path;
	const char *page_forbidden_path;
	const char *clamav_db_path;
	const char *path_temporary;
	int clamav_enabled;
	struct cl_engine *engine;
} mod_redsec_terminator_config;

int check_directory_exists(const char *path) {
    struct stat info;

    if (stat(path, &info) != 0) {
        return 0;
    } else if (info.st_mode & S_IFDIR) {
        return 1;
    } else {
        return 0;
    }
}

int write_seclang_to_file(const char *filename, char *seclang_d) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

	fprintf(file, "%s", seclang_d);
    fclose(file);

	return 0;
}

char *join_strings(apr_pool_t *pool, const char *str1, const char *str2) {
    char *result = NULL;
    if (asprintf(&result, "%s%s", str1, str2) == -1) {
        return NULL;
    }
    return apr_pstrdup(pool, result);
}

static void *create_mod_redsec_terminator_config(apr_pool_t *p, char *dir)
{
	mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)apr_pcalloc(p, sizeof(mod_redsec_terminator_config));
	config->config_path = NULL;
	config->socket_url = NULL;
	config->path_temporary = NULL;
	config->rule_path = NULL;
	config->clamav_db_path = NULL;
	config->page_forbidden_path = NULL;
	config->clamav_enabled = 0;
	config->engine = NULL;

	return (void *)config;
}

static int initialize_clamav(mod_redsec_terminator_config *config) {
	config->engine = cl_engine_new();
	if (!config->engine) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to create ClamAV engine");
	}

	// Initialize ClamAV
	if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to initialize ClamAV");
		cl_engine_free(config->engine);
	}

	// Load virus database
	const char *dbclamav = config->clamav_db_path ? config->clamav_db_path : cl_retdbdir();

	if (cl_load(dbclamav, config->engine, NULL, CL_DB_STDOPT) != CL_SUCCESS)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to load virus database from %s", dbclamav);
		cl_engine_free(config->engine);
	}

	// Compile engine after loading database
	if (cl_engine_compile(config->engine) != CL_SUCCESS)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to compile ClamAV engine");
		cl_engine_free(config->engine);
	}
	return 0;
}

static const char *enable_config_remote(cmd_parms *cmd, void *cfg, const char *arg) {
	mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)cfg;
	char *config_remote = apr_pstrdup(cmd->pool, arg);

	if (config_remote == NULL) {
		config->config_remote = 0;
		return NULL;
	} else if (strcmp(config_remote, "On") == 0) {
		config->config_remote = 1;
		return NULL;
	} else {
		config->config_remote = 0;
		return NULL;
	}

	return NULL;
}

static const char *get_seclang_remote(cmd_parms *cmd, void *cfg, const char *arg) {
	mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)cfg;

	if (config->config_remote == 1) {
		config->rule_remote_url = apr_pstrdup(cmd->pool, arg);

		if (config->rule_remote_url == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Remote URL not provided");
			return NULL;
		}

		if (config->rule_remote_url[strlen(config->rule_remote_url) - 1] != '/') {
			config->rule_remote_url = apr_pstrcat(cmd->pool, config->rule_remote_url, "/", NULL);
		}

		const char *rule_remote_url = NULL;
		asprintf(&rule_remote_url, "%s%s", config->rule_remote_url, "seclang_rules.conf.txt");

		const char *rule_unicode_remote_url = NULL;
		asprintf(&rule_unicode_remote_url, "%s%s", config->rule_remote_url, "unicode.mapping.txt");

		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Remote URL: %s", rule_unicode_remote_url);

		char *response;
		struct curl_slist *headers = NULL;

		headers = curl_slist_append(headers, "Accept: text/plain");
		headers = curl_slist_append(headers, "User-Agent: TerminatorUserAgent/1.0");

		int result = http_get(rule_remote_url, headers, &response);

		if(result == 0) {
			config->sec_rule = apr_pstrdup(cmd->pool, response);
			free(response);

			char *response_unicode;

			int result_unicode = http_get(rule_unicode_remote_url, headers, &response_unicode);

			if(result_unicode == 0) {
				config->sec_rule_unicode = apr_pstrdup(cmd->pool, response_unicode);
				free(response_unicode);
			} else {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "HTTP request secrule unicode failed");
			}
		} else {
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "HTTP request sec rule failed");
		}

		curl_slist_free_all(headers);
	}

	return NULL;
}

static const char *set_config_path(cmd_parms *cmd, void *cfg, const char *arg)
{
	mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)cfg;
	config->config_path = apr_pstrdup(cmd->pool, arg);

	const char *vhost_name = NULL;
	char *vhost_port = apr_itoa(cmd->pool, cmd->server->addrs->host_addr->port);
	char *vhost = cmd->server->addrs->virthost;

	if (strcmp(vhost, "*") == 0) {
		asprintf(&vhost_name, "%s_%s", "default", vhost_port);
	} else if (vhost == NULL) {
		asprintf(&vhost_name, "%s_%s", "default", vhost_port);
	} else {
		asprintf(&vhost_name, "%s_%s", vhost, vhost_port);
	}

	const char *cpath = NULL;
	const char *httpd_conf_path = ap_server_root_relative(cmd->pool, "terminator.conf.d/");

	if (config->config_path == NULL)
	{
		if (check_directory_exists(httpd_conf_path) == 0) {
			apr_status_t stat = apr_dir_make(httpd_conf_path, APR_OS_DEFAULT, cmd->pool);

			asprintf(&cpath, "%s%s/", httpd_conf_path, vhost_name);
			config->config_path = apr_pstrdup(cmd->pool, cpath);

			apr_dir_make(config->config_path, APR_OS_DEFAULT, cmd->pool);

			const char *seclang_rules = join_strings(cmd->pool, config->config_path, "seclang_rules.conf");
			const char *unicode_map = join_strings(cmd->pool, config->config_path, "unicode.mapping");

			apr_file_t *file_seclang;
			apr_file_open(&file_seclang, seclang_rules, APR_CREATE | APR_WRITE | APR_TRUNCATE, APR_OS_DEFAULT, cmd->pool);

			apr_file_t *file_unicode_map;
			apr_file_open(&file_unicode_map, seclang_rules, APR_CREATE | APR_WRITE | APR_TRUNCATE, APR_OS_DEFAULT, cmd->pool);

			// write seclang
			if (config->sec_rule != NULL) {
				if (write_seclang_to_file(seclang_rules, config->sec_rule) != 0) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to write seclang file");
				}
			} else {
				if (write_seclang_to_file(seclang_rules, seclang_data) != 0) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to write seclang file");
				}
			}

			if (config->sec_rule_unicode != NULL) {
				if (write_seclang_to_file(unicode_map, config->sec_rule_unicode) != 0) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to write unicode.mapping file");
				}
			} else {
				if (write_seclang_to_file(unicode_map, unicode_mapping) != 0) {
					ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to write unicode.mapping file");
				}
			}

			config->rule_path = apr_pstrdup(cmd->pool, seclang_rules);
			config->path_temporary = apr_pstrdup(cmd->pool, config->config_path);
		}
	} else {
		apr_status_t stat = apr_dir_make(config->config_path, APR_OS_DEFAULT, cmd->pool);

		asprintf(&cpath, "%s%s/", config->config_path, vhost_name);
		config->config_path = apr_pstrdup(cmd->pool, cpath);

		apr_dir_make(config->config_path, APR_OS_DEFAULT, cmd->pool);

		const char *seclang_rules = join_strings(cmd->pool, config->config_path, "seclang_rules.conf");
		const char *unicode_map = join_strings(cmd->pool, config->config_path, "unicode.mapping");

		apr_file_t *file_seclang;
		apr_file_open(&file_seclang, seclang_rules, APR_CREATE | APR_WRITE | APR_TRUNCATE, APR_OS_DEFAULT, cmd->pool);

		apr_file_t *file_unicode_map;
		apr_file_open(&file_unicode_map, seclang_rules, APR_CREATE | APR_WRITE | APR_TRUNCATE, APR_OS_DEFAULT, cmd->pool);

		// write seclang
		if (config->sec_rule != NULL) {
			if (write_seclang_to_file(seclang_rules, config->sec_rule) != 0) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to write seclang file");
			}
		} else {
			if (write_seclang_to_file(seclang_rules, seclang_data) != 0) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to write seclang file");
			}
		}

		if (config->sec_rule_unicode != NULL) {
			if (write_seclang_to_file(unicode_map, config->sec_rule_unicode) != 0) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to write unicode.mapping file");
			}
		} else {
			if (write_seclang_to_file(unicode_map, unicode_mapping) != 0) {
				ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to write unicode.mapping file");
			}
		}

		config->rule_path = apr_pstrdup(cmd->pool, seclang_rules);
		config->path_temporary = apr_pstrdup(cmd->pool, config->config_path);
	}

	return NULL;
}

static const char *set_socket_url(cmd_parms *cmd, void *cfg, const char *arg)
{
	mod_redsec_terminator_config *config = (mod_redsec_terminator_config *)cfg;
	config->socket_url = apr_pstrdup(cmd->pool, arg);

	TCPValueConfig *rules_accept = handle_config_receipt(config->socket_url);

	if (rules_accept != NULL)
	{
		config->page_forbidden_path = apr_pstrdup(cmd->pool, rules_accept->custom_mod_sec_page);
		config->rule_path = apr_pstrdup(cmd->pool, rules_accept->rules_filename);
		config->path_temporary = apr_pstrdup(cmd->pool, rules_accept->main_directory);
		config->clamav_enabled = rules_accept->clamav_status;

		if (config->clamav_enabled == 1)
		{
			config->clamav_db_path = apr_pstrdup(cmd->pool, rules_accept->clamav_DB);
			initialize_clamav(config);
		}
	}

	return NULL;
}

// TCP

static int send_to_tcp_socket(request_rec *r, const char *url, const char *data)
{
	int sockfd, status;
	struct addrinfo hints, *res, *p;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char *hostname;
	char *port_str;
	char *url_copy = apr_pstrdup(apr_hook_global_pool, url);

	if (strncmp(url_copy, "http://", 7) == 0)
	{
		url_copy += 7;
	}
	else if (strncmp(url_copy, "https://", 8) == 0)
	{
		url_copy += 8;
	}

	hostname = strtok(url_copy, ":/");
	port_str = strtok(NULL, ":/");

	if (port_str == NULL)
	{
		port_str = "80";
	}

	if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: getaddrinfo error: %s", gai_strerror(status));
	}

	for (p = res; p != NULL; p = p->ai_next)
	{
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
		{
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error opening socket");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
		{
			close(sockfd);
			ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error connecting to socket");
			continue;
		}

		break;
	}

	if (p == NULL)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Failed to connect to socket");
	}

	freeaddrinfo(res);

	int bytes_sent = send(sockfd, data, strlen(data), 0);
	if (bytes_sent == -1)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "mod_redsec_terminator: Error sending data");
		close(sockfd);
	}

	close(sockfd);
	return 0;
}

// modSec
static int modSecHandle(request_rec *r)
{
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "data: %s", r->server->server_hostname);
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "data log : %d", r->server->port);
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "request number : %d", r->method_number);
	return OK;
}

// RESPONSE modSec
static void handleResponse(request_rec *r, const char *path_url)
{
	ap_set_content_type(r, "text/html");

	apr_file_t *file;
	apr_status_t rv = apr_file_open(&file, path_url, APR_READ, APR_OS_DEFAULT, r->pool);

	if (rv != APR_SUCCESS)
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Failed to open file: %s", path_url);
		ap_rputs("<html><body><h1>Access Forbidden</h1><p>Your request was denied by the security rules.</p></body></html>", r);
		return;
	}

	char buffer[8192];
	// apr_size_t bytes_read;

	while (1)
	{
		apr_size_t buffer_size = sizeof(buffer);
		rv = apr_file_read(file, buffer, &buffer_size);

		if (rv == APR_EOF)
		{
			break;
		}
		else if (rv != APR_SUCCESS)
		{
			ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, "Error reading file: %s", path_url);
			ap_rputs("<html><body><h1>Internal Server Error</h1><p>Unable to read file.</p></body></html>", r);
			apr_file_close(file);
			return;
		}

		ap_rwrite(buffer, buffer_size, r);
	}

	apr_file_close(file);
}

// Handler
static int mod_redsec_terminator_handler(request_rec *r)
{
	ap_set_content_type(r, "text/plain");

	const char *content_type = apr_table_get(r->headers_in, "Content-Type");

	if (!content_type)
	{
		content_type = "Content-Type header not found.";
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Content-Type found: %s", content_type);
	if (content_type)
	{
		r->content_type = apr_pstrdup(r->pool, content_type);
	}

	if (apr_strnatcasecmp(r->handler, "mod_redsec_terminator"))
	{
		return DECLINED;
	}

	mod_redsec_terminator_config *config = ap_get_module_config(r->per_dir_config, &mod_redsec_terminator_module);
	if (!config || !config->socket_url)
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: Configuration not initialized properly");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	const char *url_socket = config->socket_url;
	const char *rule_path = config->rule_path;
	const char *page_forbidden_path = config->page_forbidden_path;

	json_object *json_obj = json_object_new_object();
	json_object *msc_obj = json_object_new_object();
	json_object *query_params_obj = json_object_new_object();
	json_object *body_obj = json_object_new_object();
	json_object *upload_filter = json_object_new_array();
	ModSecValuePair *modSecVal = NULL;

	if (r->args)
	{

		char *query_params = apr_pstrdup(r->pool, r->args);
		char *param_name = strtok(query_params, "&?");

		while (param_name != NULL)
		{
			char *param_value = strchr(param_name, '=');
			if (param_value)
			{
				*param_value++ = '\0';

				json_object_object_add(query_params_obj, param_name, json_object_new_string(param_value));
			}
			else
			{
				json_object_object_add(query_params_obj, param_name, json_object_new_string(""));
			}
			param_name = strtok(NULL, "&?");
		}
	}
	else
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "mod_redsec_terminator: No query parameters");
	}

	if (r->method_number == M_POST || r->method_number == M_PUT || r->method_number == M_PATCH || r->method_number == M_DELETE || r->method_number == M_GET)
	{
		const char *prefixFormData = "multipart/form-data";
		keyValuePair *formData;

		if (apr_strnatcasecmp(r->content_type, "application/json") == 0)
		{
			// formData = readJson(r)->value;
			// Read JSON value to form data
			// call key json from readJson and assign to formData
			formData = readJson(r);
		}
		else if (strncmp(r->content_type, prefixFormData, strlen(prefixFormData)) == 0)
		{
			formData = parse_multipart_form_data(r, config->path_temporary, config->clamav_enabled);
		}
		else
		{
			formData = readBody(r);
			if (formData) {
				int i;
				for (i = 0; &formData[i]; i++) {
					if (formData[i].key && formData[i].value) {
						ap_rprintf(r, "%s = %s\n", formData[i].key, formData[i].value);
					} else if (formData[i].key) {
						ap_rprintf(r, "%s\n", formData[i].key);
					} else if (formData[i].value) {
						ap_rprintf(r, "= %s\n", formData[i].value);
					} else {
						break;
					}
				}
			}
		}
		if (formData)
		{
			for (int i = 0; formData[i].key || formData[i].value; i++)
			{
				if (content_type && strncmp(content_type, "application/json", 16) == 0)
				{
					json_object *json_obj = json_tokener_parse(formData[i].value);
					json_object_object_add(body_obj, formData[i].key ? formData[i].key : NULL, json_obj);
				}
				else
				{
					json_object_object_add(body_obj, formData[i].key ? formData[i].key : "", json_object_new_string(formData[i].value ? formData[i].value : ""));
					if (formData[i].type && apr_strnatcasecmp(formData[i].type, "file") == 0 && config->clamav_enabled == 1)
					{
						char file_path[512];
						snprintf(file_path, sizeof(file_path), "%s/%s", config->path_temporary, formData[i].value);

						modSecVal = clamav_handle(r, (const char *)file_path, formData[i].value, config->engine);

						if (modSecVal != NULL)
						{

							json_object *status_message_obj = json_object_new_object();

							json_object_object_add(status_message_obj, "status", json_object_new_int64(modSecVal->status ? modSecVal->status : 200));
							json_object_object_add(status_message_obj, "message", json_object_new_string(modSecVal->message ? modSecVal->message : ""));

							json_object_array_add(upload_filter, status_message_obj);
						}
					}
				}
			}
		}
	}

	if (json_obj != NULL)
	{
		json_object_object_add(json_obj, "query_params", query_params_obj);
		json_object_object_add(json_obj, "body", body_obj);
		json_object_object_add(json_obj, "upload_filter", upload_filter);
		if (strncmp(r->protocol, "HTTP/1.1", 8) == 0)
		{
			json_object_object_add(json_obj, "protocol", json_object_new_string("http"));
		}
		else if (strncmp(r->protocol, "HTTP/2", 6) == 0)
		{
			json_object_object_add(json_obj, "protocol", json_object_new_string("https"));
		}
		json_object_object_add(json_obj, "host", json_object_new_string(r->hostname));
		json_object_object_add(json_obj, "uri", json_object_new_string(r->uri));
		json_object_object_add(json_obj, "method", json_object_new_string(r->method));
		json_object_object_add(json_obj, "remote_ip", json_object_new_string(r->useragent_ip));
		json_object_object_add(json_obj, "user_agent", json_object_new_string(apr_table_get(r->headers_in, "User-Agent")));
	}

	const char *json_str = json_object_to_json_string(json_obj);
	// MOD

	if (modSecVal == NULL)
	{
		modSecVal = mod_sec_handler(r, body_obj, rule_path, url_socket);
	}

	if (modSecVal != NULL)
	{
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL, "Processing ModSecurity Rules %ld", json_object_array_length(upload_filter));

		for (size_t i = 0; i < json_object_array_length(upload_filter); i++)
		{
			json_object *status_message_obj = json_object_array_get_idx(upload_filter, i);

			json_object *status_obj;
			json_object *message_obj;

			if (json_object_object_get_ex(status_message_obj, "status", &status_obj) &&
				json_object_object_get_ex(status_message_obj, "message", &message_obj))
			{

				int status = json_object_get_int(status_obj);
				const char *message = json_object_get_string(message_obj);

				if (status != 200 && message != NULL)
				{
					json_object_object_add(msc_obj, "status_msc", json_object_new_int(status));
					json_object_object_add(msc_obj, "message_msc", json_object_new_string(message));

					json_object_object_add(json_obj, "msc_report", msc_obj);

					const char *json_filter = json_object_to_json_string(json_obj);

					send_to_tcp_socket(r, url_socket, json_filter);

					free(modSecVal);

					handleResponse(r, page_forbidden_path);

					return OK;
				}
			}
		}

		if (modSecVal->status != 200 && modSecVal->message != NULL)
		{

			json_object_object_add(msc_obj, "status_msc", json_object_new_int(modSecVal->status));

			json_object_object_add(msc_obj, "message_msc", json_object_new_string(modSecVal->message));
			json_object_object_add(json_obj, "msc_report", msc_obj);

			const char *json_string = json_object_to_json_string(json_obj);

			send_to_tcp_socket(r, url_socket, json_string);

			free(modSecVal);
			handleResponse(r, page_forbidden_path);

			return OK;
		}

		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Log Header Content Type: %s", apr_table_get(r->headers_in, "User-Agent"));
		free(modSecVal);
	}

	send_to_tcp_socket(r, url_socket, json_str);


	return DECLINED;
}

static void mod_redsec_terminator_register_hooks(apr_pool_t *p)
{
	ap_hook_handler(mod_redsec_terminator_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec mod_redsec_terminator_cmds[] = {
	AP_INIT_TAKE1("EnableTerminatorConfigRemote", enable_config_remote, NULL, RSRC_CONF, "Enable remote configuration"),
	AP_INIT_TAKE1("SecRuleConfigRemoteURLPath", get_seclang_remote, NULL, RSRC_CONF, "Enable remote seclang configuration"),
	AP_INIT_TAKE1("RedSecTerminatorConfigPath", set_config_path, NULL, RSRC_CONF, "Specify the custom configuration path"),
	AP_INIT_TAKE1("RedSecTerminatorURLSocket", set_socket_url, NULL, RSRC_CONF, "Specify the custom socket URL for data transmission"),
	{NULL}
};

module AP_MODULE_DECLARE_DATA mod_redsec_terminator_module = {
	STANDARD20_MODULE_STUFF,
	create_mod_redsec_terminator_config,
	NULL,
	NULL,
	NULL,
	mod_redsec_terminator_cmds,
	mod_redsec_terminator_register_hooks};

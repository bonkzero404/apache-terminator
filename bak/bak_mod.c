#include <stdio.h>
#include <stdlib.h>
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"

char main_rule_uri[] = "basic_rules.conf";

int main(int argc, char **argv) {
    const char *error = NULL;
    ModSecurity *modsec = msc_init();
    if (!modsec) {
        fprintf(stderr, "Failed to initialize ModSecurity\n");
        return -1;
    }

    msc_set_connector_info(modsec, "ModSecurity-test v0.0.1-alpha (Simple example on how to use ModSecurity API)");

    RulesSet *rules = msc_create_rules_set();
    if (!rules) {
        fprintf(stderr, "Failed to create rules set\n");
        msc_cleanup(modsec);
        return -1;
    }

    // Example of adding a rules file (basic_rules.conf)
    int ret = msc_rules_add_file(rules, main_rule_uri, &error);
    if (ret < 0) {
        fprintf(stderr, "Failed to add rules file: %s\n", error);
        msc_rules_cleanup(rules);
        msc_cleanup(modsec);
        return -1;
    }

    // Example of adding a remote rules file
    ret = msc_rules_add_remote(rules, "test", "https://www.modsecurity.org/modsecurity-regression-test-secremoterules.txt", &error);
    if (ret < 0) {
        fprintf(stderr, "Failed to add remote rules: %s\n", error);
        msc_rules_cleanup(rules);
        msc_cleanup(modsec);
        return -1;
    }


    Transaction *transaction = msc_new_transaction(modsec, rules, NULL);
    if (!transaction) {
        fprintf(stderr, "Failed to create transaction\n");
        msc_rules_cleanup(rules);
        msc_cleanup(modsec);
        return -1;
    }

    // Process request with ModSecurity
    msc_process_connection(transaction, "127.0.0.1", 8282, "127.0.0.1", 8282);

    msc_process_uri(transaction,
        "http://localhost:8282/?test=tes",
        "GET", "1.1");
    msc_process_request_headers(transaction);
    msc_process_request_body(transaction);
    msc_process_response_headers(transaction, 200, "HTTP 1.3");
    msc_process_response_body(transaction);

    // msc_intervention(transaction, NULL);
    msc_process_logging(transaction);

    msc_rules_cleanup(rules);
    msc_cleanup(modsec);
    return 0;
}

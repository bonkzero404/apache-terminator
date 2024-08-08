#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

// Callback function to write data received from the server
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t total_size = size * nmemb;
    char **response_ptr = (char **)userp;

    // Reallocate memory for the response buffer
    *response_ptr = realloc(*response_ptr, total_size + 1);
    if(*response_ptr == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 0;
    }

    // Copy the data to the response buffer
    memcpy(*response_ptr, contents, total_size);
    (*response_ptr)[total_size] = '\0';

    return total_size;
}

// Function to perform an HTTP GET request with optional headers
int http_get(const char *url, const struct curl_slist *headers, char **response)
{
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(curl) {
        // Initialize response buffer
        *response = malloc(1); // Allocate initial buffer
        if(*response == NULL) {
            fprintf(stderr, "Failed to allocate memory\n");
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 1;
        }
        (*response)[0] = '\0'; // Empty response buffer

        // Set the URL for the request
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Set the write callback function
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        // Set the user pointer for the write callback
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

        // Set the headers if provided
        if (headers) {
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        // Perform the request
        res = curl_easy_perform(curl);

        // Check for errors
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            free(*response);
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 1;
        }

        // Cleanup
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    return 0;
}

int main(void)
{
    char *response;
    struct curl_slist *headers = NULL;
    int result;

    // Example of adding headers
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "User-Agent: CustomUserAgent/1.0");

    result = http_get("http://example.com", headers, &response);
    if(result == 0) {
        printf("Response:\n%s\n", response);
        free(response);
    } else {
        fprintf(stderr, "HTTP request failed\n");
    }

    // Free the header list
    curl_slist_free_all(headers);

    return 0;
}

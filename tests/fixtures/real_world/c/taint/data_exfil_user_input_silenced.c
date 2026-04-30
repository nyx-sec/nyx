#include <curl/curl.h>
#include <stdio.h>

void forward_stdin() {
    char input[256];
    if (!fgets(input, sizeof(input), stdin)) return;

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://telemetry.internal/forward");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, input);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

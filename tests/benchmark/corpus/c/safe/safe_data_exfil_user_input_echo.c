// DATA_EXFIL safe: plain user input via fgets/stdin forwarded into the
// CURLOPT_POSTFIELDS body of a fixed-URL curl request must not fire.
// Sensitivity-gate strips the cap for Plain-tier sources.
#include <curl/curl.h>
#include <stdio.h>

void forward_stdin(void) {
    char input[256];
    if (!fgets(input, sizeof(input), stdin)) return;

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://telemetry.internal/forward");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, input);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

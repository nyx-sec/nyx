// Phase 14 fixture stub — minimal servlet response shape.
public class HttpServletResponse {
    private final StringBuilder body = new StringBuilder();
    public void write(String s) { body.append(s); }
    public String getBody() { return body.toString(); }
}

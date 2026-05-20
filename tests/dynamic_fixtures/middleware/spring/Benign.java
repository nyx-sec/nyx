// Phase 21 — Spring middleware benign control.
// implements HandlerInterceptor

public class Benign {
    public boolean preHandle(String payload) {
        String safe = payload.replaceAll("[^A-Za-z0-9 _.-]", "_");
        System.out.println("intercepted: " + safe);
        return true;
    }
}

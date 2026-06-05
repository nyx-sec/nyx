import org.springframework.web.servlet.HandlerInterceptor;

class AuditInterceptor implements HandlerInterceptor {
  public boolean preHandle(Object request, Object response, Object handler) {
    return true;
  }

  public String normalize(String payload) {
    return payload;
  }
}

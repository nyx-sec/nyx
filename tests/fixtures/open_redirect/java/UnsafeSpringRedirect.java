// Phase 05 follow-up: Spring MVC controller-return open-redirect.
// `return "redirect:" + url` is Spring's view-name convention; the
// returned String becomes a 302 to whatever follows the prefix, so a
// request-supplied URL flows straight into the redirect target.
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class UnsafeSpringRedirect {
    @RequestMapping("/login/post")
    public String afterLogin(@RequestParam("next") String next, javax.servlet.http.HttpServletRequest req) {
        String target = req.getParameter("next");
        return "redirect:" + target;
    }
}

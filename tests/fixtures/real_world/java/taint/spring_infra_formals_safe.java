import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.ui.Model;
import javax.servlet.http.*;
import java.io.*;
import java.security.Principal;

@RestController
public class AccountController {
    private JdbcTemplate jdbcTemplate;

    @GetMapping("/static")
    public void staticBody(HttpServletResponse resp) throws Exception {
        resp.getWriter().write("hello");
        resp.setHeader("X-Frame-Options", "DENY");
        resp.addCookie(new Cookie("a", "b"));
    }

    @GetMapping("/stream")
    public void stream(HttpServletResponse response) throws Exception {
        OutputStream os = response.getOutputStream();
        os.write(new byte[] {1, 2});
        PrintWriter out = response.getWriter();
        out.print("{\"ok\":true}");
    }

    @GetMapping("/config")
    public void config(HttpServletRequest request) throws Exception {
        String path = request.getServletContext().getRealPath("/WEB-INF/app.properties");
        new FileInputStream(path).close();
    }

    @GetMapping("/me")
    public Object me(Principal principal) {
        return jdbcTemplate.queryForList("select * from accounts where owner = '" + principal.getName() + "'");
    }

    @GetMapping("/profile")
    public Object profile(@AuthenticationPrincipal UserDetails user) {
        return jdbcTemplate.queryForList("select * from profiles where login = '" + user.getUsername() + "'");
    }

    @GetMapping("/view")
    public String view(Model model, HttpSession session) {
        model.addAttribute("a", "b");
        session.invalidate();
        return "view";
    }
}

import java.io.OutputStream;
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class SafeSpringInfraFormals {
    @GetMapping("/logout")
    public void logout(HttpServletResponse resp, HttpSession session) throws Exception {
        session.invalidate();
        resp.addCookie(new Cookie("session", ""));
        resp.getWriter().write("bye");
    }

    @GetMapping("/ping")
    public void ping(HttpServletResponse response) throws Exception {
        OutputStream os = response.getOutputStream();
        os.write(new byte[] {'o', 'k'});
    }
}

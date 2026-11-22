import java.io.IOException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class XssStringBuilderStatement extends HttpServlet {
    // Statement-form append: the builder is mutated, then written out.
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("name");
        StringBuilder sb = new StringBuilder("<h1>");
        sb.append(name);
        sb.append("</h1>");
        resp.getWriter().write(sb.toString());
    }

    // Chained statement form on the same builder.
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String title = req.getParameter("title");
        StringBuffer page = new StringBuffer();
        page.append("<title>").append(title).append("</title>");
        resp.getWriter().println(page.toString());
    }
}

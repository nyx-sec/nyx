import javax.servlet.http.*;
import java.io.*;
import java.nio.file.*;

public class UploadServlet extends HttpServlet {
    protected void inlineSource(HttpServletRequest req) throws IOException {
        File target = new File(req.getHeader("X-File"));
        new FileInputStream(target).close();
    }

    protected void baseAndName(HttpServletRequest req) throws IOException {
        String name = req.getParameter("f");
        File f = new File("/var/data", name);
        new FileInputStream(f).close();
    }

    protected void upload(HttpServletRequest req) throws IOException {
        String name = req.getParameter("f");
        File dest = new File("/tmp/uploads", name);
        FileOutputStream out = new FileOutputStream(dest);
        out.close();
    }

    protected void copyOut(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String name = req.getParameter("f");
        File f = new File("/var/reports", name);
        Files.copy(f.toPath(), resp.getOutputStream());
    }

    protected void stringCtor(HttpServletRequest req) throws IOException {
        String param = req.getParameter("f");
        String fileName = new String(param.getBytes());
        new FileOutputStream(fileName).close();
    }

    protected void builderCtor(HttpServletRequest req) throws IOException {
        String body = req.getParameter("f");
        StringBuilder sb = new StringBuilder(body);
        Files.readString(Paths.get(sb.toString()));
    }

    protected void sanitized(HttpServletRequest req) throws IOException {
        String name = req.getParameter("f");
        String safe = sanitizePath(name);
        File f = new File("/var/data", safe);
        new FileInputStream(f).close();
    }

    protected void multipartName(HttpServletRequest req) throws Exception {
        Part part = req.getPart("file");
        File dest = new File("/srv/uploads", part.getSubmittedFileName());
        new FileOutputStream(dest).close();
    }

    protected void writeReport(HttpServletRequest req) throws IOException {
        String name = req.getParameter("f");
        File out = new File("/var/reports", name);
        try (Writer w = Files.newBufferedWriter(out.toPath())) {
            w.write("report");
        }
    }

    static String sanitizePath(String s) {
        if (s.contains("..") || s.startsWith("/") || s.startsWith("\\")) {
            return "";
        }
        return s;
    }
}

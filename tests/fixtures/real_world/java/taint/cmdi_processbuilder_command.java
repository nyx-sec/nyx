import java.io.*;
import java.util.*;
import javax.servlet.http.*;

public class ProcessCommandHandler extends HttpServlet {
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String param = request.getParameter("vector");

        List<String> argList = new ArrayList<String>();
        argList.add("sh");
        argList.add("-c");
        argList.add("echo " + param);

        ProcessBuilder pb = new ProcessBuilder();
        pb.command(argList);
        pb.start();
    }
}

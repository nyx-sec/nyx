import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.servlet.http.HttpServletResponse;
import java.sql.*;

@Path("/r")
public class ReportResource {
    private Connection conn;

    @POST
    @Path("/run")
    public void run(String payload) throws Exception {
        Runtime.getRuntime().exec(payload);
    }

    @GET
    @Path("/q")
    public void query(@Context UriInfo ui) throws Exception {
        String v = ui.getQueryParameters().getFirst("v");
        conn.createStatement().executeQuery("select * from t where a = '" + v + "'");
    }

    @GET
    @Path("/h")
    public void header(@Context HttpHeaders headers) throws Exception {
        String v = headers.getHeaderString("X-V");
        conn.createStatement().executeQuery("select * from t where a = '" + v + "'");
    }

    @GET
    @Path("/static")
    public void staticBody(@Context HttpServletResponse response) throws Exception {
        response.getWriter().write("static");
        response.addHeader("X-A", "b");
    }

    @GET
    @Path("/role")
    public void role(@Context SecurityContext sc) throws Exception {
        String user = sc.getUserPrincipal().getName();
        conn.createStatement().executeQuery("select role from users where name = '" + user + "'");
    }
}

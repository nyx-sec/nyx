// Unsafe: Apache FreeMarker constructor takes a tainted template *source*
// string (the second arg to `new Template(name, reader, cfg)` is read
// once into the compiled body), then `tpl.process(model, out)` renders
// it.  Without `TypeKind::Template`, idiomatic `Template tpl = new
// Template(...); tpl.process(...)` shapes do not type-qualify
// `tpl.process` to `Template.process`, so the existing flat SSTI rule
// never fires.
import freemarker.template.Configuration;
import freemarker.template.Template;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class UnsafeFreemarkerProcess {
    public String render(HttpServletRequest req) throws Exception {
        String src = req.getParameter("template");
        Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
        Template tpl = new Template("user", new StringReader(src), cfg);
        Map<String, Object> model = new HashMap<>();
        model.put("user", req.getParameter("name"));
        StringWriter out = new StringWriter();
        tpl.process(model, out);
        return out.toString();
    }
}

// Phase 04 (Track J.2) — Java Thymeleaf SSTI vuln fixture.
//
// The body reaches TemplateEngine.process directly, so an attacker
// who controls the body can render arbitrary Thymeleaf expressions.
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

public class Vuln {
    public static String run(String body) {
        TemplateEngine engine = new TemplateEngine();
        Context ctx = new Context();
        return engine.process(body, ctx);
    }
}

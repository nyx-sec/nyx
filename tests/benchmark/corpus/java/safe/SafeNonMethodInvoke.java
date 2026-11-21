import java.util.function.Function;
import javax.management.MBeanServer;
import javax.management.ObjectName;

public class SafeNonMethodInvoke {
    interface Invocation { Object invoke(String realm); }

    private final Invocation invoker;
    SafeNonMethodInvoke(Invocation invoker) { this.invoker = invoker; }

    private Object invoke(Function<String, Object> f, String resource) {
        return f.apply(resource);
    }

    Object bare(String realm) {
        return invoke(r -> r.length(), realm);
    }

    Object typedField(String ctx) {
        return this.invoker.invoke(ctx);
    }

    Object jmx(MBeanServer server, ObjectName name) throws Exception {
        return server.invoke(name, "shutdown", null, null);
    }
}

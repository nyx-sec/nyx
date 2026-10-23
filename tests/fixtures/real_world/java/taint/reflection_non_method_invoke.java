import java.util.function.Function;
import javax.management.MBeanServer;
import javax.management.ObjectName;

public class ReflectionNonMethodInvoke {
    interface Invocation { Object invoke(String realm); }
    interface Customizer { void customize(StringBuilder b); }

    static class Callbacks {
        void invoke(java.util.function.Consumer<Customizer> action) {}
    }

    private final Invocation invoker;
    ReflectionNonMethodInvoke(Invocation invoker) { this.invoker = invoker; }

    private Object invoke(Function<String, Object> f, String resource) {
        return f.apply(resource);
    }

    Object bareHelper(String realm) {
        return invoke(r -> r.length(), realm);
    }

    Object viaThis(String realm) {
        return this.invoke(r -> r.length(), realm);
    }

    void lambdaArgument(Callbacks cbs, StringBuilder b) {
        cbs.invoke(c -> c.customize(b));
    }

    Object typedField(String ctx) {
        return this.invoker.invoke(ctx);
    }

    Object typedParameter(Invocation inv, String realm) {
        return inv.invoke(realm);
    }

    Object jmx(MBeanServer server, ObjectName name) throws Exception {
        return server.invoke(name, "shutdown", null, null);
    }
}

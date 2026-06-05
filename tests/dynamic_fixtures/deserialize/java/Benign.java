// Phase 03 (Track J.1) — Java deserialize benign fixture.
//
// Same shape as the vuln fixture but wraps `ObjectInputStream` in a
// subclass whose `resolveClass` only accepts a tiny allowlist.  A
// gadget chain never resolves so no Deserialize probe fires.
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Benign {
    static final Set<String> ALLOWED =
        new HashSet<>(Arrays.asList("java.lang.Integer", "java.lang.String"));

    static class RestrictedObjectInputStream extends ObjectInputStream {
        RestrictedObjectInputStream(ByteArrayInputStream s) throws IOException {
            super(s);
        }
        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (!ALLOWED.contains(desc.getName())) {
                throw new InvalidClassException("blocked: " + desc.getName());
            }
            return super.resolveClass(desc);
        }
    }

    public static Object run(byte[] payload) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(payload);
        try (RestrictedObjectInputStream ois = new RestrictedObjectInputStream(bis)) {
            return ois.readObject();
        }
    }
}

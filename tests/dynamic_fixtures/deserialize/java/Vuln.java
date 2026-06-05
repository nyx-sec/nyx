// Phase 03 (Track J.1) — Java deserialize vuln fixture.
//
// The function reads bytes off the wire and hands them straight to
// `ObjectInputStream.readObject` without restricting `resolveClass`.
// A gadget chain inside the byte stream is materialised before any
// allowlist check fires, so a CVE-class object-injection is reachable.
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class Vuln {
    public static Object run(byte[] payload) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(payload);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }
}

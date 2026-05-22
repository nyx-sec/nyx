// Phase 11 (Track J.9) — Java CRYPTO vuln fixture.
//
// Models a config-driven crypto endpoint that picks the RNG based on
// the request payload — `*_WEAK` routes through `java.util.Random`
// (a non-CSPRNG, seeded from the payload hash, returning a 16-bit
// key) and `*_STRONG` routes through `java.security.SecureRandom`
// (a CSPRNG, returning 32 bytes).  This shape is needed by the
// differential runner: the vuln-payload attempt and the benign-
// control attempt both load the same fixture, and only the payload-
// routed weak branch trips the `WeakKeyEntropy` predicate.
import java.util.Random;
import java.security.SecureRandom;

public class Vuln {
    public static byte[] run(String value) {
        if (value != null && value.contains("STRONG")) {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            return key;
        }
        Random r = new Random(value == null ? 0L : (long) value.hashCode());
        byte[] key = new byte[2];
        r.nextBytes(key);
        return key;
    }
}

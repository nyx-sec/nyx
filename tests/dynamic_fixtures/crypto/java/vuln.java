// Phase 11 (Track J.9) — Java CRYPTO vuln fixture.
//
// Uses java.util.Random (a non-CSPRNG) to derive key bytes, producing
// a key bounded inside a 16-bit search space.  The harness's
// instrumented key-generation path writes a `ProbeKind::WeakKey`
// probe; the `WeakKeyEntropy` oracle fires for `key_int < 2^16`.
import java.util.Random;

public class Vuln {
    public static byte[] run(String seedTag) {
        Random r = new Random(seedTag.hashCode());
        byte[] key = new byte[2];
        r.nextBytes(key);
        return key;
    }
}

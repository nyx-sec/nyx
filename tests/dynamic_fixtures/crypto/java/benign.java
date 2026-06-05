// Phase 11 (Track J.9) — Java CRYPTO benign control fixture.
//
// Uses java.security.SecureRandom (a CSPRNG) for key derivation, so
// the produced 256-bit key trivially exceeds the 16-bit weak budget.
import java.security.SecureRandom;

public class Benign {
    public static byte[] run(String _unused) {
        SecureRandom r = new SecureRandom();
        byte[] key = new byte[32];
        r.nextBytes(key);
        return key;
    }
}

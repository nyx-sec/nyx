// Phase 11 (Track J.9) — Java UNAUTHORIZED_ID vuln fixture.
import java.util.HashMap;
import java.util.Map;

public class Vuln {
    private static final String CALLER = "alice";
    private static final Map<String, String> STORE = new HashMap<>();
    static {
        STORE.put("alice", "alice@x");
        STORE.put("bob", "bob@x");
    }

    public static String run(String ownerId) {
        return STORE.get(ownerId);
    }
}

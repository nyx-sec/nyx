// Phase 11 (Track J.9) — Java UNAUTHORIZED_ID benign control fixture.
import java.util.HashMap;
import java.util.Map;

public class Benign {
    private static final String CALLER = "alice";
    private static final Map<String, String> STORE = new HashMap<>();
    static {
        STORE.put("alice", "alice@x");
        STORE.put("bob", "bob@x");
    }

    public static String run(String ownerId) {
        if (!CALLER.equals(ownerId)) return null;
        return STORE.get(ownerId);
    }
}

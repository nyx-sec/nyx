// Resources acquired inside Java try-with-resources must not propagate
// an Acquire effect onto callers' receivers.  The acquire node is
// `managed_resource = true` after CFG lowering, so the method-summary
// builder skips it.
//
// Pre-fix: methods like `void load(File f) { try (var in = new
// FileInputStream(f)) { ... } }` were summarised as Acquire, so callers
// `obj.load(f)` got `obj` marked OPEN.
import java.io.FileInputStream;

public class SafeLoader {
    public void load(java.io.File f) throws Exception {
        try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
            in.read();
        }
    }

    public static void useLoader(java.io.File f) throws Exception {
        SafeLoader loader = new SafeLoader();
        loader.load(f);
    }
}

// Java JSON_PARSE depth-bomb vuln fixture.
//
// Models a config-driven JSON ingest endpoint that picks the parser
// input based on the request payload tag - `*_DEEP` routes through a
// deeply-nested array literal (256 levels) that drives the parser past
// the 64-level depth budget; `*_SHALLOW` routes through a flat `[]`
// parse that leaves the predicate clear.  This shape is needed by the
// differential runner: the vuln-payload attempt and the benign-control
// attempt both load the same fixture, and only the payload-routed
// deep branch trips the `JsonParseExcessiveDepth` predicate.
//
// Java has no stdlib JSON parser.  The harness ships a hand-rolled
// iterative `NyxJsonProbe.parse(String)` helper alongside `NyxHarness`
// so the fixture does not need to link Jackson / Gson at build time.
// The helper returns a `java.util.List` / `java.util.Map` tree the
// harness then walks via `NyxJsonProbe.countDepth(Object)` to produce
// the `ProbeKind::JsonParse { depth }` record.
public class Vuln {
    public static Object run(String value) {
        String text = value == null ? "" : value;
        if (text.contains("DEEP")) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 256; i++) {
                sb.append('[');
            }
            for (int i = 0; i < 256; i++) {
                sb.append(']');
            }
            return NyxJsonProbe.parse(sb.toString());
        }
        return NyxJsonProbe.parse("[]");
    }
}

// File I/O — adversarial collision fixture.
// Prints the path-traversal canary marker unconditionally without reading any
// file and without emitting __NYX_SINK_HIT__, so the oracle observes a marker
// hit with no sink-reachability.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: Entry.readFile(String)  Cap: FILE_IO

public class Entry {
    public static void readFile(String userPath) {
        // Coincidental oracle match — emits the marker string but is not a
        // file-read sink and never reaches the planted canary.  Must match the
        // CANARY_MARKER in src/dynamic/corpus/path_trav/java.rs.
        System.out.println("NYX_PATHTRAVERSAL_R34D_a7f3c1d8 present");
        int x = userPath.length();
    }
}

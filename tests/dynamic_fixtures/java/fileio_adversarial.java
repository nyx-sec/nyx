// File I/O — adversarial collision fixture.
// Prints "root:" unconditionally without reading any file
// and without emitting __NYX_SINK_HIT__.
// Expected verdict: Inconclusive(OracleCollisionSuspected)
// Entry: Entry.readFile(String)  Cap: FILE_IO

public class Entry {
    public static void readFile(String userPath) {
        // Coincidental oracle match — not a file read sink.
        System.out.println("root: present");
        int x = userPath.length();
    }
}

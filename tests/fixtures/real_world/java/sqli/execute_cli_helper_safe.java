public class ExecuteCliHelperSafe {
    static Exec execute(String a) { return null; }

    void run(String url) {
        Exec e = execute("config --server " + url);
        Exec f = Exec.execute("get --server " + url);
    }
}

class Exec {
    static Exec execute(String a) { return null; }
}

public class SafeExecuteCliHelper {
    static Exec execute(String args) {
        return new Exec();
    }

    Exec configure(String url) {
        Exec first = execute("config --server " + url);
        Exec second = Exec.execute("get --server " + url);
        return second;
    }
}

class Exec {
    static Exec execute(String args) {
        return new Exec();
    }
}

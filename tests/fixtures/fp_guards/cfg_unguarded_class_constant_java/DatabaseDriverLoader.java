package org.example.util;

public class DatabaseDriverLoader {
    private static final String MYSQL_DRIVER = "com.mysql.cj.jdbc.Driver";
    private static final String POSTGRESQL_DRIVER = "org.postgresql.Driver";
    private static final String H2_DRIVER = "org.h2.Driver";
    private static final int CONNECT_TIMEOUT_MS = 5000;

    public static void loadDriver(String connectionUrl) throws ClassNotFoundException {
        if (connectionUrl.contains("jdbc:mysql")) {
            Class.forName(MYSQL_DRIVER);
        } else if (connectionUrl.contains("jdbc:postgresql")) {
            Class.forName(POSTGRESQL_DRIVER);
        } else if (connectionUrl.contains("jdbc:h2")) {
            Class.forName(H2_DRIVER);
        }
    }

    public static int timeoutMs() {
        Thread.sleep(CONNECT_TIMEOUT_MS);
        return CONNECT_TIMEOUT_MS;
    }
}

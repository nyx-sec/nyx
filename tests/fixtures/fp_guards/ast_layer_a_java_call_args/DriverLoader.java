package guards;

import java.security.MessageDigest;

public class DriverLoader {

    private static final String MYSQL_DRIVER = "com.mysql.cj.jdbc.Driver";
    private static final String POSTGRES_DRIVER = "org.postgresql.Driver";

    public void loadKnownDriverByLiteral() throws Exception {
        Class.forName("com.mysql.cj.jdbc.Driver");
    }

    public void loadKnownDriverByConst() throws Exception {
        Class.forName(MYSQL_DRIVER);
        Class.forName(POSTGRES_DRIVER);
    }

    public void loadCallerSuppliedDriver(String driver) throws Exception {
        Class.forName(driver);
    }

    public byte[] hashWithLiteralAlgo() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest("payload".getBytes());
    }
}

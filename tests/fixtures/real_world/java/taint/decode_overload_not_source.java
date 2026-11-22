import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Base64;

public class SerializationUtil {
    public static Object decode(String encoded, ClassLoader classLoader) {
        try {
            byte[] bytes = Base64.getMimeDecoder().decode(encoded);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            return ois.readObject();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Throwable decodeException(String result) {
        try {
            byte[] bytes = Base64.getDecoder().decode(result);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
            return (Throwable) ois.readObject();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

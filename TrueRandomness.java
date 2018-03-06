
import java.security.SecureRandom;


public class TrueRandomness {
    public static final int NumBytes = 32;

    private static boolean alreadyUsed = false;

    public static byte[] get() {
        // Provides <NumBytes> bytes of (assumed to be) random data
        // This can only be called once; assertion will fail if called again

        if (alreadyUsed)
            throw new RuntimeException("TrueRandomness .get() has already been used.");

        byte[] ret = new byte[NumBytes];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(ret);
        alreadyUsed = true;
        return ret;
    }
}

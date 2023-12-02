import android.util.Log;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;

public class FileEncryptionManager {

    static { Security.addProvider(new BouncyCastleProvider()); }

    public static void encryptFile(String input, String output) {
        processFile(Cipher.ENCRYPT_MODE, input, output);
        Log.d("Encryption", "File encrypted successfully");
    }

    public static void decryptFile(String input, String output) {
        processFile(Cipher.DECRYPT_MODE, input, output);
        Log.d("Decryption", "File decrypted successfully");
    }

    private static void processFile(int mode, String input, String output) {
        try {
            SecretKey key = KeyGenerator.getInstance("AES", "BC").generateKey();
            Cipher cipher = Cipher.getInstance("AES", "BC");
            cipher.init(mode, key);

            try (InputStream in = new FileInputStream(input);
                 OutputStream out = new FileOutputStream(output);
                 CipherOutputStream cipherOut = new CipherOutputStream(out, cipher)) {

                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = in.read(buffer)) != -1) {
                    cipherOut.write(buffer, 0, bytesRead);
                }
            }
        } catch (Exception e) { e.printStackTrace(); }
    }
}

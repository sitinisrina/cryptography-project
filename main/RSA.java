import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSA {
    
    private static final int KEY_SIZE = 2048;
    private static final String ALGORITHM = "RSA";
    private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /**
     * Fungsi generateKeyPair mengggenarate kunci baru, PK dan SK.
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM); //getInstance() adalah concrete method yang generate public/private key
        keyGen.initialize(KEY_SIZE); //inisialisasi for certain key size.
        return keyGen.generateKeyPair();
    }

    /**
     * Encrypt plaintext using public key with OAEP padding
     */
    public static byte[] encrypt(byte[] plaintext, PublicKey publicKey) throws Exception {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    /**
     * Decrypt ciphertext using private key with OAEP padding
     */
    public static byte[] decrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext cannot be null or empty");
        }

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }
}

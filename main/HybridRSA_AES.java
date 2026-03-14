import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class HybridRSA_AES {

    // Generate AES session key
    public static SecretKey generateSessionKey() throws Exception {
        return AES.generateAESKey();
    }

    // Encrypt session key with RSA public key
    public static byte[] encryptSessionKey(SecretKey sessionKey, PublicKey publicKey) throws Exception {
        return RSA.encrypt(sessionKey.getEncoded(), publicKey);
    }

    // Decrypt session key with RSA private key
    public static SecretKey decryptSessionKey(byte[] encryptedSessionKey, PrivateKey privateKey) throws Exception {
        byte[] keyBytes = RSA.decrypt(encryptedSessionKey, privateKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    // Encrypt message with AES
    public static byte[] encryptMessage(byte[] plaintext, SecretKey sessionKey) throws Exception {
        return AES.encrypt(plaintext, sessionKey);
    }

    // Decrypt message with AES
    public static byte[] decryptMessage(byte[] ciphertext, SecretKey sessionKey) throws Exception {
        return AES.decrypt(ciphertext, sessionKey);
    }
}
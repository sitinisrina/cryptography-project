import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/*
1. generate kunci sesi AES dengan AES.generateAESKey()
2. generate public key dan private key RSA dengan RSA.generateKeyPair()
3. Enkripsi kunci sesi AES yang sudah di-generate dengan RSA public key, RSA.encrypt(plaintext, publicKey)
4. Enkripsi plaintext/message dengan kunci sesi AES, AES.encrypt(plaintextBytes, key)
5. Dekripsi kunci sesi AES dengan RSA private key, RSA.decrypt(ciphertext, privateKey)
6. Dekripsi ciphertext dengan kunci sesi AES (yang sudah terekripsi), AES.decrypt(ivAndCiphertext, key)
*/

public class HybridRSA_AES {

    //1. Generate RSA key pair
    public static KeyPair generateRSAKeyPair() throws Exception {
        return RSA.generateKeyPair();
    }

    //2. Generate AES session key
    public static SecretKey generateSessionKey() throws Exception {
        return AES.generateAESKey();
    }

    //3. Encrypt session key with RSA public key
    public static byte[] encryptSessionKey(SecretKey sessionKey, PublicKey publicKey) throws Exception {
        return RSA.encrypt(sessionKey.getEncoded(), publicKey);
    }

    //4. Decrypt session key with RSA private key
    public static SecretKey decryptSessionKey(byte[] encryptedSessionKey, PrivateKey privateKey) throws Exception {
        byte[] keyBytes = RSA.decrypt(encryptedSessionKey, privateKey);
        return new SecretKeySpec(keyBytes, "AES");
    }

    //5. Encrypt message with AES
    public static byte[] encryptMessage(byte[] plaintext, SecretKey sessionKey) throws Exception {
        return AES.encrypt(plaintext, sessionKey);
    }

    //6. Decrypt message with AES
    public static byte[] decryptMessage(byte[] ciphertext, SecretKey sessionKey) throws Exception {
        return AES.decrypt(ciphertext, sessionKey);
    }
}
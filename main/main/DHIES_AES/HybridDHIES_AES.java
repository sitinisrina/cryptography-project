package main.DHIES_AES;

import main.AES;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class HybridDHIES_AES {
    public static class HybridEncryptData {
        private final byte[] salt;
        private final byte[] ciphertext;

        public HybridEncryptData(byte[] salt, byte[] ciphertext) {
            this.salt = salt;
            this.ciphertext = ciphertext;
        }

        public byte[] getSalt() {
            return salt;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

    }

    public static HybridEncryptData encrypt(byte[] plaintext, byte[] sharedSecret) throws Exception {
        if(plaintext == null || sharedSecret == null) {
            throw new IllegalArgumentException("Plaintext and shared secret cannot be null");
        }
        byte[] salt = DHIES.generateRandomSalt();
        SecretKey aesKey = DHIES.deriveAESKey(sharedSecret, salt);

        byte[] ciphertext = AES.encrypt(plaintext, aesKey);
        return new HybridEncryptData(salt, ciphertext);
    }

    public static byte[] decrypt(HybridEncryptData encryptData, byte[] sharedSecret) throws Exception {
        if(encryptData == null || sharedSecret == null) {
            throw new IllegalArgumentException("Encrypt data and shared secret cannot be null");
        }
        if(encryptData.getSalt() == null || encryptData.getCiphertext() == null) {
            throw new IllegalArgumentException("Encrypt data must contain both salt and ciphertext");
        }
        SecretKey aesKey = DHIES.deriveAESKey(sharedSecret, encryptData.getSalt());
        return AES.decrypt(encryptData.getCiphertext(), aesKey);
    }
}
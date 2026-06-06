package main.DHIES_AES;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.util.Arrays;

public class HybridDHIES_AES {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public static class HybridEncryptData {
        private final byte[] ciphertext;
        private final byte[] tag;

        public HybridEncryptData(byte[] ciphertext, byte[] tag) {
            this.ciphertext = ciphertext;
            this.tag = tag;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }

        public byte[] getTag() {
            return tag;
        }
    }

    public static HybridEncryptData encrypt(byte[] plaintext, byte[] sharedSecret) throws Exception {
        if (plaintext == null || sharedSecret == null) {
            throw new IllegalArgumentException("Plaintext dan shared secret tidak boleh null.");
        }

        DHIES.DerivedKeys derivedKeys = DHIES.deriveKeys(sharedSecret);

        SecretKey encKey = derivedKeys.getEncKey();
        SecretKey macKey = derivedKeys.getMacKey();

        byte[] ciphertext = AES_DHIES.encrypt(plaintext, encKey);
        byte[] tag = generateTag(ciphertext, macKey);

        return new HybridEncryptData(ciphertext, tag);
    }

    public static byte[] decrypt(HybridEncryptData encryptData, byte[] sharedSecret) throws Exception {
        if (encryptData == null || sharedSecret == null) {
            throw new IllegalArgumentException("Encrypt data dan shared secret tidak boleh null.");
        }

        if (encryptData.getCiphertext() == null || encryptData.getTag() == null) {
            throw new IllegalArgumentException("Encrypt data harus berisi ciphertext dan tag.");
        }

        DHIES.DerivedKeys derivedKeys = DHIES.deriveKeys(sharedSecret);

        SecretKey encKey = derivedKeys.getEncKey();
        SecretKey macKey = derivedKeys.getMacKey();

        byte[] recalculatedTag = generateTag(encryptData.getCiphertext(), macKey);

        if (!constantTimeEquals(encryptData.getTag(), recalculatedTag)) {
            throw new SecurityException("Verifikasi MAC gagal. Ciphertext tidak valid atau telah dimodifikasi.");
        }

        return AES_DHIES.decrypt(encryptData.getCiphertext(), encKey);
    }

    private static byte[] generateTag(byte[] ciphertext, SecretKey macKey) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(macKey);
        return mac.doFinal(ciphertext);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        return Arrays.equals(a, b);
    }
}
package main.DHIES_AES;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES_DHIES {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final int IV_LENGTH = 16;

    public static byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static byte[] encrypt(byte[] plaintextBytes, SecretKey key) {
        if (plaintextBytes == null || key == null) {
            throw new IllegalArgumentException("Plaintext dan key tidak boleh null.");
        }

        try {
            byte[] iv = generateIV();

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

            byte[] ciphertext = cipher.doFinal(plaintextBytes);

            byte[] out = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length);

            return out;

        } catch (Exception e) {
            throw new RuntimeException("Encrypt AES-CTR gagal", e);
        }
    }

    public static byte[] decrypt(byte[] ivAndCiphertext, SecretKey key) {
        if (ivAndCiphertext == null || key == null) {
            throw new IllegalArgumentException("Ciphertext dan key tidak boleh null.");
        }

        if (ivAndCiphertext.length < IV_LENGTH) {
            throw new IllegalArgumentException("Data terenkripsi tidak valid atau terlalu pendek.");
        }

        try {
            byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(ivAndCiphertext, IV_LENGTH, ivAndCiphertext.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            return cipher.doFinal(ciphertext);

        } catch (Exception e) {
            throw new RuntimeException("Gagal melakukan dekripsi AES-CTR", e);
        }
    }
}
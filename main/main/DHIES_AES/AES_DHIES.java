package main.DHIES_AES;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES_DHIES {

    private static final String ALGORITHM = "AES/CTR/NoPadding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    public static final int IV_LENGTH = 16;
    public static final int HMAC_TAG_SIZE = 32;

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

    /**
     * Streams plaintext from plainIn to encOut (IV prepended), computing
     * HMAC-SHA256(IV || ciphertext) simultaneously.
     * Returns the 32-byte HMAC tag.
     */
    public static byte[] encryptToStreamWithMAC(InputStream plainIn, OutputStream encOut,
            SecretKey encKey, SecretKey macKey) throws Exception {
        byte[] iv = generateIV();
        encOut.write(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, encKey, new IvParameterSpec(iv));

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(macKey);
        mac.update(iv);

        byte[] buf = new byte[8 * 1024 * 1024];
        int n;
        while ((n = plainIn.read(buf)) != -1) {
            byte[] enc = cipher.update(buf, 0, n);
            if (enc != null) {
                mac.update(enc);
                encOut.write(enc);
            }
        }
        byte[] tail = cipher.doFinal();
        if (tail != null && tail.length > 0) {
            mac.update(tail);
            encOut.write(tail);
        }
        return mac.doFinal();
    }

    /**
     * Verifies HMAC-SHA256(ivAndCiphertext) == expectedTag, then
     * stream-decrypts ivAndCiphertext (in-memory) to plainOut in 8 MB chunks.
     * Throws SecurityException if tag mismatch — no plaintext is written in that case.
     */
    public static void decryptToStreamVerified(byte[] ivAndCiphertext, OutputStream plainOut,
            SecretKey encKey, SecretKey macKey, byte[] expectedTag) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(macKey);
        mac.update(ivAndCiphertext);
        if (!Arrays.equals(expectedTag, mac.doFinal())) {
            throw new SecurityException("Verifikasi MAC gagal. Ciphertext tidak valid atau telah dimodifikasi.");
        }

        if (ivAndCiphertext.length < IV_LENGTH) {
            throw new IllegalArgumentException("Data terenkripsi terlalu pendek.");
        }
        byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, IV_LENGTH);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, encKey, new IvParameterSpec(iv));

        int offset = IV_LENGTH;
        int chunkSize = 8 * 1024 * 1024;
        while (offset < ivAndCiphertext.length) {
            int len = Math.min(chunkSize, ivAndCiphertext.length - offset);
            byte[] dec = cipher.update(ivAndCiphertext, offset, len);
            if (dec != null) plainOut.write(dec);
            offset += len;
        }
        byte[] tail = cipher.doFinal();
        if (tail != null) plainOut.write(tail);
    }

    /**
     * Reads exactly ivAndCiphertextLen bytes from encIn (IV + ciphertext),
     * decrypts to plainOut in 8 MB chunks. Does NOT verify HMAC — caller
     * must verify before calling.
     */
    public static void decryptFromStream(InputStream encIn, OutputStream plainOut,
            SecretKey key, long ivAndCiphertextLen) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        readFully(encIn, iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        long remaining = ivAndCiphertextLen - IV_LENGTH;
        byte[] buf = new byte[8 * 1024 * 1024];
        while (remaining > 0) {
            int toRead = (int) Math.min(buf.length, remaining);
            int n = encIn.read(buf, 0, toRead);
            if (n == -1) throw new RuntimeException("Stream berakhir sebelum waktunya.");
            byte[] dec = cipher.update(buf, 0, n);
            if (dec != null) plainOut.write(dec);
            remaining -= n;
        }
        byte[] tail = cipher.doFinal();
        if (tail != null) plainOut.write(tail);
    }

    public static void readFully(InputStream in, byte[] buf) throws Exception {
        int offset = 0;
        while (offset < buf.length) {
            int r = in.read(buf, offset, buf.length - offset);
            if (r == -1) throw new RuntimeException("Stream berakhir sebelum waktunya saat membaca data.");
            offset += r;
        }
    }
}

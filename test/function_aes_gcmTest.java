import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.SecretKey;

public class function_aes_gcmTest {

    @Test
    void encryptDecrypt_shouldReturnOriginalPlaintext() throws Exception {
        SecretKey key = function_aes_gcm.generateAESKey();
        String plaintext = "Halo AES-GCM! Ini unit test.";

        byte[] encrypted = function_aes_gcm.encryptString(plaintext, key);
        String decrypted = function_aes_gcm.decryptToString(encrypted, key);

        assertEquals(plaintext, decrypted);
    }

    @Test
    void encryptSamePlaintextTwice_shouldProduceDifferentCiphertext() throws Exception {
        SecretKey key = function_aes_gcm.generateAESKey();
        String plaintext = "Pesan yang sama";

        byte[] encrypted1 = function_aes_gcm.encryptString(plaintext, key);
        byte[] encrypted2 = function_aes_gcm.encryptString(plaintext, key);

        assertNotNull(encrypted1);
        assertNotNull(encrypted2);
        assertFalse(java.util.Arrays.equals(encrypted1, encrypted2),
                "Ciphertext seharusnya berbeda karena IV random");
    }

    @Test
    void tamperedPayload_shouldFailDecryption() throws Exception {
        SecretKey key = function_aes_gcm.generateAESKey();
        String plaintext = "Pesan rahasia";

        byte[] encrypted = function_aes_gcm.encryptString(plaintext, key);

        // Ubah 1 byte di bagian akhir payload
        encrypted[encrypted.length - 1] ^= 1;

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            function_aes_gcm.decryptToString(encrypted, key);
        });

        assertTrue(ex.getMessage().contains("Authentication tag tidak valid")
                || ex.getCause() != null);
    }

    @Test
    void wrongKey_shouldFailDecryption() throws Exception {
        SecretKey correctKey = function_aes_gcm.generateAESKey();
        SecretKey wrongKey = function_aes_gcm.generateAESKey();
        String plaintext = "Ini harus gagal kalau key salah";

        byte[] encrypted = function_aes_gcm.encryptString(plaintext, correctKey);

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            function_aes_gcm.decryptToString(encrypted, wrongKey);
        });

        assertTrue(ex.getMessage().contains("Authentication tag tidak valid")
                || ex.getCause() != null);
    }

    @Test
    void tooShortPayload_shouldThrowIllegalArgumentException() throws Exception {
        SecretKey key = function_aes_gcm.generateAESKey();

        byte[] invalidPayload = new byte[5];

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            function_aes_gcm.decrypt(invalidPayload, key);
        });

        assertTrue(ex.getMessage().contains("terlalu pendek")
                || ex.getMessage().contains("tidak valid"));
    }

    @Test
    void emptyPlaintext_shouldStillEncryptAndDecrypt() throws Exception {
        SecretKey key = function_aes_gcm.generateAESKey();
        String plaintext = "";

        byte[] encrypted = function_aes_gcm.encryptString(plaintext, key);
        String decrypted = function_aes_gcm.decryptToString(encrypted, key);

        assertEquals(plaintext, decrypted);
        assertNotNull(encrypted);
        assertTrue(encrypted.length >= 28); // 12 byte IV + 16 byte tag minimum
    }
}
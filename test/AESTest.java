import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

public class AESTest {

    @Test
    void encryptDecrypt_shouldReturnOriginalPlaintext() throws Exception {
        SecretKey key = AES.generateAESKey();
        String plaintext = "Halo AES-GCM! Ini unit test.";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        byte[] encryptedBytes = AES.encrypt(plaintextBytes, key);
        byte[] decryptedBytes = AES.decrypt(encryptedBytes, key);

        assertArrayEquals(plaintextBytes, decryptedBytes);
    }

    @Test
    void encryptSamePlaintextTwice_shouldProduceDifferentCiphertext() throws Exception {
        SecretKey key = AES.generateAESKey();
        String plaintext = "Pesan yang sama";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted1 = AES.encrypt(plaintextBytes, key);
        byte[] encrypted2 = AES.encrypt(plaintextBytes, key);

        assertNotNull(encrypted1);
        assertNotNull(encrypted2);
        assertFalse(java.util.Arrays.equals(encrypted1, encrypted2),
                "Ciphertext seharusnya berbeda karena IV random");
    }

    @Test
    void tamperedPayload_shouldFailDecryption() throws Exception {
        SecretKey key = AES.generateAESKey();
        String plaintext = "Pesan rahasia";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = AES.encrypt(plaintextBytes, key);

        // Ubah 1 byte di bagian akhir payload
        encrypted[encrypted.length - 1] ^= 1;

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            AES.decrypt(encrypted, key);
        });

        assertTrue(ex.getMessage().contains("Authentication tag tidak valid")
                || ex.getCause() != null);
    }

    @Test
    void wrongKey_shouldFailDecryption() throws Exception {
        SecretKey correctKey = AES.generateAESKey();
        SecretKey wrongKey = AES.generateAESKey();
        String plaintext = "Ini harus gagal kalau key salah";
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = AES.encrypt(plaintextBytes, correctKey);

        RuntimeException ex = assertThrows(RuntimeException.class, () -> {
            AES.decrypt(encrypted, wrongKey);
        });

        assertTrue(ex.getMessage().contains("Authentication tag tidak valid")
                || ex.getCause() != null);
    }

    @Test
    void tooShortPayload_shouldThrowIllegalArgumentException() throws Exception {
        SecretKey key = AES.generateAESKey();

        byte[] invalidPayload = new byte[5];

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> {
            AES.decrypt(invalidPayload, key);
        });

        assertTrue(ex.getMessage().contains("terlalu pendek")
                || ex.getMessage().contains("tidak valid"));
    }

    @Test
    void emptyPlaintext_shouldStillEncryptAndDecrypt() throws Exception {
        SecretKey key = AES.generateAESKey();
        byte[] plaintextBytes = new byte[0];

        byte[] encrypted = AES.encrypt(plaintextBytes, key);
        byte[] decrypted = AES.decrypt(encrypted, key);

        assertArrayEquals(plaintextBytes, decrypted);
        assertNotNull(encrypted);
        assertTrue(encrypted.length >= 28); // 12 byte IV + 16 byte tag minimum
    }

    @Test
    void encryptedBytes_hexEncodeDecode_shouldRemainSame() throws Exception {
        SecretKey key = AES.generateAESKey();
        byte[] plaintext = "Halo".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = AES.encrypt(plaintext, key);

        String hex = Helper.fromBinaryToHexa(encrypted);
        byte[] decoded = Helper.fromHexaToBinary(hex);

        assertArrayEquals(encrypted, decoded);
    }

    @Test
    void encryptedBytes_base64EncodeDecode_shouldRemainSame() throws Exception {
        SecretKey key = AES.generateAESKey();
        byte[] plaintext = "Halo".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = AES.encrypt(plaintext, key);

        String base64 = Helper.fromBinaryToBase64(encrypted);
        byte[] decoded = Helper.fromBase64ToBinary(base64);

        assertArrayEquals(encrypted, decoded);
    }

    @Test
    void encryptToHexAndBack_shouldStillDecryptCorrectly() throws Exception {
        SecretKey key = AES.generateAESKey();
        byte[] plaintext = "Pesan uji".getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = AES.encrypt(plaintext, key);
        String hex = Helper.fromBinaryToHexa(encrypted);
        byte[] decodedEncrypted = Helper.fromHexaToBinary(hex);
        byte[] decrypted = AES.decrypt(decodedEncrypted, key);

        assertArrayEquals(plaintext, decrypted);
    }
}
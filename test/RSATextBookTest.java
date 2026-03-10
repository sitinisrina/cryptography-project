import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class RSATextBookTest {

    @Test
    void shouldGenerateValidKeyPair() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublicKey());
        assertNotNull(keyPair.getPrivateKey());

        assertNotNull(keyPair.getPublicKey().getModulus());
        assertNotNull(keyPair.getPublicKey().getE());
        assertNotNull(keyPair.getPrivateKey().getModulus());
        assertNotNull(keyPair.getPrivateKey().getD());

        assertEquals(
            keyPair.getPublicKey().getModulus(),
            keyPair.getPrivateKey().getModulus()
        );

        assertEquals(2048, keyPair.getPublicKey().getModulus().bitLength());
    }

    @Test
    void shouldEncryptAndDecryptShortMessage() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();
        byte[] plaintext = "Hello RSA".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = RSATextbook.encrypt(plaintext, keyPair.getPublicKey());
        byte[] decrypted = RSATextbook.decrypt(ciphertext, keyPair.getPrivateKey());

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void ciphertextShouldHaveFixedBlockSize() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();
        byte[] plaintext = "Test".getBytes(StandardCharsets.UTF_8);

        byte[] ciphertext = RSATextbook.encrypt(plaintext, keyPair.getPublicKey());

        assertEquals(256, ciphertext.length);
    }

    @Test
    void shouldEncryptAndDecryptSingleByte() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();
        byte[] plaintext = new byte[] { 42 };

        byte[] ciphertext = RSATextbook.encrypt(plaintext, keyPair.getPublicKey());
        byte[] decrypted = RSATextbook.decrypt(ciphertext, keyPair.getPrivateKey());

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void shouldEncryptAndDecryptMaxAllowedMessage() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();

        byte[] plaintext = new byte[254];
        Arrays.fill(plaintext, (byte) 65);

        byte[] ciphertext = RSATextbook.encrypt(plaintext, keyPair.getPublicKey());
        byte[] decrypted = RSATextbook.decrypt(ciphertext, keyPair.getPrivateKey());

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void shouldThrowExceptionWhenPlaintextIsNull() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> RSATextbook.encrypt(null, keyPair.getPublicKey())
        );

        assertEquals("Plaintext cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionWhenPlaintextIsEmpty() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> RSATextbook.encrypt(new byte[0], keyPair.getPublicKey())
        );

        assertEquals("Plaintext cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionWhenCiphertextIsNull() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> RSATextbook.decrypt(null, keyPair.getPrivateKey())
        );

        assertEquals("Ciphertext cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionWhenCiphertextIsEmpty() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> RSATextbook.decrypt(new byte[0], keyPair.getPrivateKey())
        );

        assertEquals("Ciphertext cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldThrowExceptionWhenMessageTooLong() {
        RSATextbook.RSAKeyPair keyPair = RSATextbook.generateKeyPair();

        byte[] plaintext = new byte[255];

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> RSATextbook.encrypt(plaintext, keyPair.getPublicKey())
        );

        assertEquals("Message is too long for encryption", exception.getMessage());
    }
}
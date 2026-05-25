import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

import main.Helper;

public class HybridTest {
    
    @Test
    void testOriginalFileSameAsDecryptedFile() throws Exception {

        byte[] original = Helper.fromFiletoBinary("original_text.pdf");
        byte[] decrypted = Helper.fromFiletoBinary("decrypted_message.pdf");

        assertArrayEquals(original, decrypted);    }

}

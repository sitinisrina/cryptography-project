/*
TAHAP 1
bob membangkitkan pasangan kunci RSA dengan HybridRSA_AES.generateRSAKeyPair()

TAHAP 2
bob menerima encrypted session key dari alice.
bob mendekripsi session key tersebut dengan kunci privat miliknya, HybridRSA_AES.decryptSessionKey(encryptedSessionKey, privateKey)

TAHAP 3
bob membaca dan mengubah ciphertext yang dikirim alice terlebih dahulu ke byte, Helper.fromFiletoBinary(filepath)
bob mendekripsi ciphertext dengan HybridRSA_AES.decryptMessage(ciphertext, sessionKey)
*/

import java.util.Scanner;

public class PovBobasReceiver {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Masukkan path file encrypted session key: ");
        String encryptedSessionKeyPath = scanner.nextLine();
        System.out.print("Masukkan path file encrypted message: ");
        String encryptedMessagePath = scanner.nextLine();   

        try {
            // 1. Take Bob's RSA private key
            var bobPrivateKey = Helper.loadPrivateKey("bob_private_key.bin", "RSA");

            // 2. Read encrypted session key and message from files
            var encryptedSessionKey = Helper.fromFiletoBinary(encryptedSessionKeyPath);
            var encryptedMessage = Helper.fromFiletoBinary(encryptedMessagePath);

            // 3. Decrypt AES session key with RSA private key
            var sessionKey = HybridRSA_AES.decryptSessionKey(encryptedSessionKey, bobPrivateKey);

            // 4. Decrypt message with AES session key
            var decryptedMessage = HybridRSA_AES.decryptMessage(encryptedMessage, sessionKey);

            // 5. Write a file for decrypted message
            Helper.writeBinarytoFile(decryptedMessage, "decrypted_message.pdf");

            System.out.println("Pesan berhasil didekripsi dan disimpan sebagai 'decrypted_message.pdf'.");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}

package main.DHIES_AES;

import main.Helper;
import java.util.Scanner;

public class DHIESBobasReceiver {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Masukkan path file encrypted message: ");
        String encryptedMessagePath = scanner.nextLine();

        try {
            // Load Bob's DH private key
            var bobPrivateKey = Helper.loadPrivateKey("bob_DH_private_key.bin", "DH");

            // Load Alice's ephemeral public key
            var aliceEphemeralPublicKey = Helper.loadPublicKey("alice_ephemeral_public_key.bin", "DH");

            // Compute shared secret: Bob private key x Alice ephemeral public key
            byte[] sharedSecret = DHIES.computeSharedSecret(
                    bobPrivateKey,
                    aliceEphemeralPublicKey
            );

            // Read encrypted message from file
            var encryptedMessage = Helper.fromFiletoBinary(encryptedMessagePath);

            // Read salt from file
            var salt = Helper.fromFiletoBinary("dhies_salt.bin");

            // Bungkus menjadi object HybridEncryptedData
            HybridDHIES_AES.HybridEncryptData hybridData =
                    new HybridDHIES_AES.HybridEncryptData(salt, encryptedMessage);

            // Decrypt message
            var decryptedMessage = HybridDHIES_AES.decrypt(hybridData, sharedSecret);

            // Write decrypted message to file
            Helper.writeBinarytoFile(decryptedMessage, "decrypted_DHIES_message.txt");
            System.out.println("Pesan berhasil didekripsi dan disimpan sebagai 'decrypted_DHIES_message.txt'.");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
package main.DHIES_AES;

import main.Helper;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class DHIESBobasReceiver {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file encrypted message: ");
            String encryptedMessagePath = scanner.nextLine();

            // Load private key Bob (static private key receiver)
            PrivateKey bobPrivateKey = Helper.loadPrivateKey("bob_DH_private_key.bin", "DH");

            // Load ephemeral public key Alice (komponen U)
            PublicKey aliceEphemeralPublicKey = Helper.loadPublicKey("alice_ephemeral_public_key.bin", "DH");

            // Compute shared secret: Bob private key x Alice ephemeral public key
            byte[] sharedSecret = DHIES.computeSharedSecret(
                    bobPrivateKey,
                    aliceEphemeralPublicKey
            );

            // Read ciphertext from file
            byte[] encryptedMessage = Helper.fromFiletoBinary(encryptedMessagePath);

            // Read salt from file
            byte[] salt = Helper.fromFiletoBinary("dhies_salt.bin");

            // Read authentication tag from file
            byte[] tag = Helper.fromFiletoBinary("dhies_tag.bin");

            // Bungkus menjadi objek HybridEncryptData
            HybridDHIES_AES.HybridEncryptData hybridData =
                    new HybridDHIES_AES.HybridEncryptData(salt, encryptedMessage, tag);

            // Decrypt message (MAC akan diverifikasi terlebih dahulu)
            byte[] decryptedMessage = HybridDHIES_AES.decrypt(hybridData, sharedSecret);

            // Write decrypted message to file
            Helper.writeBinarytoFile(decryptedMessage, "decrypted_DHIES_message.txt");

            System.out.println("Pesan berhasil didekripsi dan disimpan sebagai 'decrypted_DHIES_message.txt'.");

        } catch (SecurityException e) {
            System.err.println("Verifikasi MAC gagal. Ciphertext tidak valid atau telah dimodifikasi.");
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Terjadi kesalahan saat proses dekripsi DHIES-AES:");
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
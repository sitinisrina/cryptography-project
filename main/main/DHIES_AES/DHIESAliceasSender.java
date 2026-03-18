package main.DHIES_AES;

import main.Helper;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class DHIESAliceasSender {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Masukkan path file yang ingin dikirim: ");
        String filePath = scanner.nextLine();

        try {
            // Load Bob's public key
            PublicKey bobPublicKey = Helper.loadPublicKey("bob_DH_public_key.bin", "DH");

            // Load Alice's private key from file
            PrivateKey alicePrivateKey = Helper.loadPrivateKey("alice_DH_private_key.bin", "DH");

            //compute shared secret
            byte[] sharedSecret = HybridDHIES_AES.computeSharedSecret(alicePrivateKey, bobPublicKey);

            //derive AES session key from shared secret
            var sessionKey = HybridDHIES_AES.deriveAESKey(sharedSecret);

            //encrypt message with AES session key
            var fileContent = Helper.fromFiletoBinary(filePath);
            var encryptedFileContent = HybridDHIES_AES.encryptMessage(fileContent, sessionKey);

            // Save the encrypted file
            Helper.writeBinarytoFile(encryptedFileContent, "encrypted_DHIES_file.bin");
            System.out.println("File berhasil dienkripsi dan disimpan sebagai 'encrypted_DHIES_file.bin'.");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}

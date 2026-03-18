package main.DHIES_AES;

import main.Helper;
import java.util.Scanner;

public class DHIESBobasReceiver {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Masukkan path file encrypted message: ");
        String encryptedMessagePath = scanner.nextLine();  
        
        try {
            //load Bob's DH private key
            var bobPrivateKey = Helper.loadPrivateKey("bob_DH_private_key.bin", "DH");

            //load Alice's DH public key
            var alicePublicKey = Helper.loadPublicKey("alice_DH_public_key.bin", "DH");

            //compute shared secret
            byte[] sharedSecret = HybridDHIES_AES.computeSharedSecret(bobPrivateKey, alicePublicKey);

            //derive AES session key from shared secret
            var sessionKey = HybridDHIES_AES.deriveAESKey(sharedSecret);

            //read encrypted message from file
            var encryptedMessage = Helper.fromFiletoBinary(encryptedMessagePath);

            //decrypt message with AES session key
            var decryptedMessage = HybridDHIES_AES.decryptMessage(encryptedMessage, sessionKey);

            //write decrypted message to file
            Helper.writeBinarytoFile(decryptedMessage, "decrypted_DHIES_message.txt");
            System.out.println("Pesan berhasil didekripsi dan disimpan sebagai 'decrypted_DHIES_message.txt'.");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }

    }
}

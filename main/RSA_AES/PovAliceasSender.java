package main.RSA_AES;

import main.Helper;
import java.util.Scanner;

/*
TAHAP 1
alice membangkitkan pasangan kunci RSA dengan HybridRSA_AES.generateRSAKeyPair()
alice mengambil bob public key dari file "bob_public_key.bin" dengan Helper.loadPublicKey("bob_public_key.bin")

TAHAP 2
alice membangkitkan kunci sesi AES dengan HybridRSA_AES.generateSessionKey()
alice mengenkripsi kunci sesi AES dengan kunci publik Bob (65537), HybridRSA_AES.encryptSessionKey(sessionKey, publicKey)
alice menyimpan encrypted session key, untuk dikirimkan bersamaan dengan cipher text.

TAHAP 3
alice menginput plaintext (apapun) dari user dengan scanner
alice mengenkripsi plaintext dengan HybridRSA_AES.encryptMessage(plaintext, sessionKey)
alice encoding hasil cipher text dan encrypted session key, kemudian dikirim ke Bob.

*/

public class PovAliceasSender {
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Masukkan path file yang ingin dikirim: ");
        String filePath = scanner.nextLine();

        try {
            // 1. Take Bob's RSA public key
            var bobPublicKey = Helper.loadPublicKey("bob_public_key.bin", "RSA");

            // 2. Generate AES session key
            var sessionKey = HybridRSA_AES.generateSessionKey();

            // 3. Encrypt AES session key with RSA public key
            var encryptedSessionKey = HybridRSA_AES.encryptSessionKey(sessionKey, bobPublicKey);

            // 4. Encrypt file content with AES session key
            var fileContent = Helper.fromFiletoBinary(filePath);
            var encryptedFileContent = HybridRSA_AES.encryptMessage(fileContent, sessionKey);

            // 5. Save encrypted data to files
            Helper.writeBinarytoFile(encryptedSessionKey, "encrypted_session_key.bin");
            Helper.writeBinarytoFile(encryptedFileContent, "encrypted_file.bin");

            System.out.println("File berhasil dienkripsi dan disimpan sebagai 'encrypted_session_key.bin' dan 'encrypted_file.bin'.");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }

    }
}

package main.DHIES_AES;

import main.Helper;
import java.security.KeyPair;
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

            // Generate Alice ephemeral key pair untuk setiap pengiriman
            KeyPair aliceEphemeralKeyPair = DHIES.generateKeyPairFromPeerPublicKey(bobPublicKey);

            // Compute shared secret: Alice ephemeral private key x Bob public key
            byte[] sharedSecret = DHIES.computeSharedSecret(
                    aliceEphemeralKeyPair.getPrivate(),
                    bobPublicKey
            );

            // Baca file yang akan dienkripsi
            byte[] fileContent = Helper.fromFiletoBinary(filePath);

            // Encrypt file content menggunakan hybrid DHIES-AES
            HybridDHIES_AES.HybridEncryptData encryptedResult =
                    HybridDHIES_AES.encrypt(fileContent, sharedSecret);

            // Simpan ciphertext
            Helper.writeBinarytoFile(
                    encryptedResult.getCiphertext(),
                    "encrypted_DHIES_file.bin"
            );

            // Simpan salt HKDF
            Helper.writeBinarytoFile(
                    encryptedResult.getSalt(),
                    "dhies_salt.bin"
            );

            // Simpan ephemeral public key Alice
            Helper.writeBinarytoFile(
                    aliceEphemeralKeyPair.getPublic().getEncoded(),
                    "alice_ephemeral_public_key.bin"
            );

            System.out.println("File berhasil dienkripsi.");
            System.out.println("Ciphertext disimpan sebagai 'encrypted_DHIES_file.bin'.");
            System.out.println("Salt disimpan sebagai 'dhies_salt.bin'.");
            System.out.println("Ephemeral public key disimpan sebagai 'alice_ephemeral_public_key.bin'.");

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
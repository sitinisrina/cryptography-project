package main.DHIES_AES;

import main.Helper;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;

public class DHIESAliceasSender {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file yang ingin dikirim: ");
            String filePath = scanner.nextLine();

            // Load public key Bob (static public key receiver)
            PublicKey bobPublicKey = Helper.loadPublicKey("bob_DH_public_key.bin", "DH");

            // Generate ephemeral key pair Alice untuk setiap pengiriman
            KeyPair aliceEphemeralKeyPair = DHIES.generateKeyPairFromPeerPublicKey(bobPublicKey);

            // Compute shared secret: Alice ephemeral private key x Bob public key
            byte[] sharedSecret = DHIES.computeSharedSecret(
                    aliceEphemeralKeyPair.getPrivate(),
                    bobPublicKey
            );

            // Baca file plaintext yang akan dikirim
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

            // Simpan authentication tag / MAC
            Helper.writeBinarytoFile(
                    encryptedResult.getTag(),
                    "dhies_tag.bin"
            );

            // Simpan ephemeral public key Alice (komponen U)
            Helper.writeBinarytoFile(
                    aliceEphemeralKeyPair.getPublic().getEncoded(),
                    "alice_ephemeral_public_key.bin"
            );

            System.out.println("File berhasil dienkripsi dengan skema DHIES-AES.");
            System.out.println("Ciphertext disimpan sebagai 'encrypted_DHIES_file.bin'.");
            System.out.println("Salt disimpan sebagai 'dhies_salt.bin'.");
            System.out.println("Tag disimpan sebagai 'dhies_tag.bin'.");
            System.out.println("Ephemeral public key disimpan sebagai 'alice_ephemeral_public_key.bin'.");

        } catch (Exception e) {
            System.err.println("Terjadi kesalahan saat proses enkripsi DHIES-AES:");
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
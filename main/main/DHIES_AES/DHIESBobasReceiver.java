package main.DHIES_AES;

import main.Helper;
import main.BenchmarkHelper;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class DHIESBobasReceiver {

    public static byte[] decryptMode(byte[] encryptedPackage, PrivateKey bobPrivateKey) throws Exception {
        byte[][] parsedPackage = Helper.parseDHIESPackage(encryptedPackage);

        byte[] aliceEphemeralPublicKeyBytes = parsedPackage[0];
        byte[] salt = parsedPackage[1];
        byte[] ciphertext = parsedPackage[2];
        byte[] tag = parsedPackage[3];

        PublicKey aliceEphemeralPublicKey =
                Helper.loadPublicKeyFromBytes(aliceEphemeralPublicKeyBytes, "DH");

        byte[] sharedSecret = DHIES.computeSharedSecret(
                bobPrivateKey,
                aliceEphemeralPublicKey
        );

        HybridDHIES_AES.HybridEncryptData hybridData =
                new HybridDHIES_AES.HybridEncryptData(salt, ciphertext, tag);

        return HybridDHIES_AES.decrypt(hybridData, sharedSecret);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file encrypted message: ");
            String encryptedMessagePath = scanner.nextLine();

            PrivateKey bobPrivateKey = Helper.loadPrivateKey("bob_DH_private_key.bin", "DH");
            byte[] encryptedPackage = Helper.fromFiletoBinary(encryptedMessagePath);

            final byte[][] holder = new byte[1][];

            BenchmarkHelper.BenchmarkResult benchmarkResult = BenchmarkHelper.measure(() -> {
                holder[0] = decryptMode(encryptedPackage, bobPrivateKey);
            });

            byte[] decryptedMessage = holder[0];
            String decryptedHash = Helper.sha256(decryptedMessage);

            Helper.writeBinarytoFile(decryptedMessage, "decrypted_DHIES_message.mp4");

            BenchmarkHelper.writeBenchmarkResult(
                    "bob_benchmark.txt",
                    "Bob",
                    benchmarkResult
            );

            System.out.println("Hash SHA-256 hasil dekripsi     : " + decryptedHash);
            System.out.println("Pesan berhasil didekripsi dan disimpan sebagai 'decrypted_DHIES_message.mp4'.");
            System.out.println("Hasil benchmark Bob disimpan sebagai 'bob_benchmark.txt'.");

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
package main.DHIES_AES;

import main.Helper;
import main.BenchmarkHelper;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;

public class DHIESAliceasSender {

    public static byte[] encryptMode(byte[] fileContent, PublicKey bobPublicKey) throws Exception {
        KeyPair aliceEphemeralKeyPair = DHIES.generateKeyPairFromPeerPublicKey(bobPublicKey);

        byte[] sharedSecret = DHIES.computeSharedSecret(
                aliceEphemeralKeyPair.getPrivate(),
                bobPublicKey
        );

        HybridDHIES_AES.HybridEncryptData encryptedResult = HybridDHIES_AES.encrypt(fileContent, sharedSecret);

        byte[] ephemeralPublicKey = aliceEphemeralKeyPair.getPublic().getEncoded();
        byte[] salt = encryptedResult.getSalt();
        byte[] ciphertext = encryptedResult.getCiphertext();
        byte[] tag = encryptedResult.getTag();

        return Helper.buildEncryptedPackage(ephemeralPublicKey, salt, ciphertext, tag);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file yang ingin dikirim: ");
            String filePath = scanner.nextLine();

            PublicKey bobPublicKey = Helper.loadPublicKey("bob_DH_public_key.bin", "DH");
            byte[] fileContent = Helper.fromFiletoBinary(filePath);

            final byte[][] holder = new byte[1][];

            BenchmarkHelper.BenchmarkResult benchmarkResult = BenchmarkHelper.measure(() -> {
                holder[0] = encryptMode(fileContent, bobPublicKey);
            });

            byte[] encryptedPackage = holder[0];

            Helper.writeBinarytoFile(encryptedPackage, "encrypted_DHIES_file.bin");

            BenchmarkHelper.writeBenchmarkResult(
                    "alice_benchmark.txt",
                    "Alice",
                    benchmarkResult
            );

            System.out.println("File berhasil dienkripsi dengan skema DHIES-AES.");
            System.out.println("Seluruh komponen DHIES (ephemeral public key, salt, tag, ciphertext) disimpan dalam satu file: 'encrypted_DHIES_file.bin'.");
            System.out.println("Hasil benchmark Alice disimpan sebagai 'alice_benchmark.txt'.");

        } catch (Exception e) {
            System.err.println("Terjadi kesalahan saat proses enkripsi DHIES-AES:");
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
package main.RSA_AES;

import main.BenchmarkHelper;
import main.Helper;

import java.nio.ByteBuffer;
import java.util.Scanner;

public class PovAliceasSender {

    public static byte[] buildEncryptedPackage(byte[] encryptedSessionKey, byte[] encryptedFileContent) {
        if (encryptedSessionKey == null || encryptedFileContent == null) {
            throw new IllegalArgumentException("Komponen paket RSA-AES tidak boleh null.");
        }

        int totalLength = Integer.BYTES * 2
                + encryptedSessionKey.length
                + encryptedFileContent.length;

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        buffer.putInt(encryptedSessionKey.length);
        buffer.put(encryptedSessionKey);
        buffer.putInt(encryptedFileContent.length);
        buffer.put(encryptedFileContent);

        return buffer.array();
    }

    public static byte[] encryptMode(byte[] fileContent) throws Exception {
        var bobPublicKey = Helper.loadPublicKey("bob_rsa_public_key.bin", "RSA");

        var sessionKey = HybridRSA_AES.generateSessionKey();
        var encryptedSessionKey = HybridRSA_AES.encryptSessionKey(sessionKey, bobPublicKey);
        var encryptedFileContent = HybridRSA_AES.encryptMessage(fileContent, sessionKey);

        return buildEncryptedPackage(encryptedSessionKey, encryptedFileContent);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file yang ingin dikirim: ");
            String filePath = scanner.nextLine();

            byte[] fileContent = Helper.fromFiletoBinary(filePath);
            final byte[][] holder = new byte[1][];

            BenchmarkHelper.BenchmarkResult benchmarkResult = BenchmarkHelper.measure(() -> {
                holder[0] = encryptMode(fileContent);
            });

            byte[] encryptedPackage = holder[0];

            Helper.writeBinarytoFile(encryptedPackage, "encrypted_rsa_aes_package.bin");

            BenchmarkHelper.writeBenchmarkResult(
                    "alice_RSA_benchmark.txt",
                    "Alice",
                    benchmarkResult
            );

            System.out.println("File berhasil dienkripsi dengan skema RSA-AES.");
            System.out.println("Encrypted session key dan encrypted file disimpan dalam satu file: 'encrypted_rsa_aes_package.bin'.");
            System.out.println("Hasil benchmark Alice disimpan sebagai 'alice_RSA_benchmark.txt'.");

        } catch (Exception e) {
            System.err.println("Terjadi kesalahan saat proses enkripsi RSA-AES:");
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
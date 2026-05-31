package main.RSA_AES;

import main.BenchmarkHelper;
import main.Helper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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

    public static void encryptFileToOutput(String inputPath, String outputPath) throws Exception {
        var bobPublicKey = Helper.loadPublicKey("bob_rsa_public_key.bin", "RSA");
        var sessionKey = HybridRSA_AES.generateSessionKey();
        var encryptedSessionKey = HybridRSA_AES.encryptSessionKey(sessionKey, bobPublicKey);

        try (DataOutputStream dos = new DataOutputStream(
                 new BufferedOutputStream(new FileOutputStream(outputPath)));
             BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputPath))) {
            dos.writeInt(encryptedSessionKey.length);
            dos.write(encryptedSessionKey);
            dos.flush();
            AES.encryptToStream(bis, dos, sessionKey);
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file yang ingin dikirim: ");
            String filePath = scanner.nextLine();

            // Load file and generate keys outside the benchmark so timing reflects pure crypto only
            byte[] fileContent = Helper.fromFiletoBinary(filePath);
            String originalHash = Helper.sha256(fileContent);

            var bobPublicKey = Helper.loadPublicKey("bob_rsa_public_key.bin", "RSA");
            var sessionKey = HybridRSA_AES.generateSessionKey();
            var encryptedSessionKey = HybridRSA_AES.encryptSessionKey(sessionKey, bobPublicKey);

            ByteArrayOutputStream resultBaos = new ByteArrayOutputStream();
            BenchmarkHelper.BenchmarkResult benchmarkResult = BenchmarkHelper.measure(() -> {
                DataOutputStream dos = new DataOutputStream(resultBaos);
                dos.writeInt(encryptedSessionKey.length);
                dos.write(encryptedSessionKey);
                dos.flush();
                AES.encryptToStream(new ByteArrayInputStream(fileContent), dos, sessionKey);
            });

            Helper.writeBinarytoFile(resultBaos.toByteArray(), "encrypted_rsa_aes_package.bin");

            // String ciphertextPackageHash = Helper.sha256(encryptedPackage);

            System.out.println("Hash SHA-256 file asli          : " + originalHash);
            // System.out.println("Hash SHA-256 paket ciphertext   : " + ciphertextPackageHash);

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
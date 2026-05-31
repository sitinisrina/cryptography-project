package main.RSA_AES;

import main.BenchmarkHelper;
import main.Helper;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.util.Scanner;

public class PovBobasReceiver {

    public static byte[][] parseEncryptedPackage(byte[] encryptedPackage) {
        if (encryptedPackage == null || encryptedPackage.length == 0) {
            throw new IllegalArgumentException("Paket RSA-AES tidak boleh null atau kosong.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(encryptedPackage);

        if (buffer.remaining() < Integer.BYTES) {
            throw new IllegalArgumentException("Format paket RSA-AES tidak valid.");
        }

        int encryptedSessionKeyLength = buffer.getInt();
        if (encryptedSessionKeyLength < 0 || buffer.remaining() < encryptedSessionKeyLength) {
            throw new IllegalArgumentException("Panjang encrypted session key tidak valid.");
        }

        byte[] encryptedSessionKey = new byte[encryptedSessionKeyLength];
        buffer.get(encryptedSessionKey);

        if (buffer.remaining() < Integer.BYTES) {
            throw new IllegalArgumentException("Format paket RSA-AES tidak valid.");
        }

        int encryptedFileLength = buffer.getInt();
        if (encryptedFileLength < 0 || buffer.remaining() < encryptedFileLength) {
            throw new IllegalArgumentException("Panjang encrypted file content tidak valid.");
        }

        byte[] encryptedFileContent = new byte[encryptedFileLength];
        buffer.get(encryptedFileContent);

        if (buffer.hasRemaining()) {
            throw new IllegalArgumentException("Format paket RSA-AES tidak valid: ada data berlebih.");
        }

        return new byte[][] { encryptedSessionKey, encryptedFileContent };
    }

    public static void decryptFileFromInput(String inputPath, String outputPath) throws Exception {
        var bobPrivateKey = Helper.loadPrivateKey("bob_rsa_private_key.bin", "RSA");

        DataInputStream dis = new DataInputStream(
            new BufferedInputStream(new FileInputStream(inputPath)));
        int encKeyLen = dis.readInt();
        byte[] encryptedSessionKey = new byte[encKeyLen];
        dis.readFully(encryptedSessionKey);

        var sessionKey = HybridRSA_AES.decryptSessionKey(encryptedSessionKey, bobPrivateKey);
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputPath))) {
            AES.decryptFromStream(dis, bos, sessionKey);
        } finally {
            dis.close();
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file encrypted package: ");
            String encryptedPackagePath = scanner.nextLine();

            // Load package and parse header outside the benchmark so timing reflects pure crypto only
            byte[] encPackage = Helper.fromFiletoBinary(encryptedPackagePath);
            var bobPrivateKey = Helper.loadPrivateKey("bob_rsa_private_key.bin", "RSA");

            DataInputStream headerDis = new DataInputStream(new ByteArrayInputStream(encPackage));
            int encKeyLen = headerDis.readInt();
            byte[] encryptedSessionKey = new byte[encKeyLen];
            headerDis.readFully(encryptedSessionKey);
            var sessionKey = HybridRSA_AES.decryptSessionKey(encryptedSessionKey, bobPrivateKey);
            // headerDis now positioned at IV — remaining bytes = IV + ciphertext + tag
            byte[] remaining = encPackage;
            int offset = Integer.BYTES + encKeyLen;

            ByteArrayOutputStream resultBaos = new ByteArrayOutputStream();
            BenchmarkHelper.BenchmarkResult benchmarkResult = BenchmarkHelper.measure(() -> {
                AES.decryptFromStream(
                    new ByteArrayInputStream(remaining, offset, remaining.length - offset),
                    resultBaos, sessionKey);
            });

            byte[] decryptedMessage = resultBaos.toByteArray();
            String decryptedHash = Helper.sha256(decryptedMessage);
            Helper.writeBinarytoFile(decryptedMessage, "decrypted_message.mp4");

            BenchmarkHelper.writeBenchmarkResult(
                    "bob_RSA_benchmark.txt",
                    "Bob",
                    benchmarkResult
            );

            System.out.println("Hash SHA-256 hasil dekripsi     : " + decryptedHash);   
            System.out.println("Pesan berhasil didekripsi dan disimpan sebagai 'decrypted_message.mp4'.");
            System.out.println("Hasil benchmark Bob disimpan sebagai 'bob_RSA_benchmark.txt'.");

        } catch (Exception e) {
            System.err.println("Terjadi kesalahan saat proses dekripsi RSA-AES:");
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }
}
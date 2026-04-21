package main.RSA_AES;

import main.BenchmarkHelper;
import main.Helper;

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

    public static byte[] decryptMode(byte[] encryptedPackage) throws Exception {
        var bobPrivateKey = Helper.loadPrivateKey("bob_rsa_private_key.bin", "RSA");

        byte[][] parsed = parseEncryptedPackage(encryptedPackage);
        byte[] encryptedSessionKey = parsed[0];
        byte[] encryptedFileContent = parsed[1];

        var sessionKey = HybridRSA_AES.decryptSessionKey(encryptedSessionKey, bobPrivateKey);
        return HybridRSA_AES.decryptMessage(encryptedFileContent, sessionKey);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file encrypted package: ");
            String encryptedPackagePath = scanner.nextLine();

            byte[] encryptedPackage = Helper.fromFiletoBinary(encryptedPackagePath);
            final byte[][] holder = new byte[1][];

            BenchmarkHelper.BenchmarkResult benchmarkResult = BenchmarkHelper.measure(() -> {
                holder[0] = decryptMode(encryptedPackage);
            });

            byte[] decryptedMessage = holder[0];
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
package main.DHIES_AES;

import main.Helper;
import main.BenchmarkHelper;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Scanner;

public class DHIESBobasReceiver {

    // Kept for backward compat — used by old in-memory tests
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

    /**
     * Streaming decryption for large files — reads DHIES streaming package from
     * inputPath, verifies HMAC (pass 1), then decrypts to outputPath (pass 2).
     * No ciphertext is written until the MAC is verified.
     */
    public static void decryptFileFromInput(String inputPath, String outputPath) throws Exception {
        PrivateKey bobPrivateKey = Helper.loadPrivateKey("bob_DH_private_key.bin", "DH");

        byte[] ephPubKeyBytes;
        byte[] salt;
        long ivAndCiphertextLen;
        int headerSize;

        // Parse header
        try (DataInputStream dis = new DataInputStream(
                new BufferedInputStream(new FileInputStream(inputPath)))) {
            int ephPubKeyLen = dis.readInt();
            ephPubKeyBytes = new byte[ephPubKeyLen];
            dis.readFully(ephPubKeyBytes);
            int saltLen = dis.readInt();
            salt = new byte[saltLen];
            dis.readFully(salt);
            ivAndCiphertextLen = dis.readLong();
            headerSize = 4 + ephPubKeyLen + 4 + saltLen + 8;
        }

        PublicKey aliceEphemeralPublicKey = Helper.loadPublicKeyFromBytes(ephPubKeyBytes, "DH");
        byte[] sharedSecret = DHIES.computeSharedSecret(bobPrivateKey, aliceEphemeralPublicKey);
        DHIES.DerivedKeys derivedKeys = DHIES.deriveKeys(sharedSecret, salt);

        // Pass 1: verify HMAC — no output written yet (security-correct for Encrypt-then-MAC)
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(derivedKeys.getMacKey());
        mac.update(salt);
        try (DataInputStream verifyDis = new DataInputStream(
                new BufferedInputStream(new FileInputStream(inputPath)))) {
            AES_DHIES.readFully(verifyDis, new byte[headerSize]); // skip header
            byte[] buf = new byte[8 * 1024 * 1024];
            long remaining = ivAndCiphertextLen;
            while (remaining > 0) {
                int toRead = (int) Math.min(buf.length, remaining);
                int n = verifyDis.read(buf, 0, toRead);
                if (n == -1) throw new RuntimeException("Stream berakhir sebelum waktunya.");
                mac.update(buf, 0, n);
                remaining -= n;
            }
            byte[] recalcTag = mac.doFinal();
            byte[] expectedTag = new byte[AES_DHIES.HMAC_TAG_SIZE];
            verifyDis.readFully(expectedTag);
            if (!Arrays.equals(recalcTag, expectedTag)) {
                throw new SecurityException("Verifikasi MAC gagal. Ciphertext tidak valid atau telah dimodifikasi.");
            }
        }

        // Pass 2: decrypt (MAC already verified above)
        try (DataInputStream decryptDis = new DataInputStream(
                new BufferedInputStream(new FileInputStream(inputPath)));
             BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputPath))) {
            AES_DHIES.readFully(decryptDis, new byte[headerSize]); // skip header
            AES_DHIES.decryptFromStream(decryptDis, bos, derivedKeys.getEncKey(), ivAndCiphertextLen);
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file encrypted message: ");
            String encryptedMessagePath = scanner.nextLine();

            PrivateKey bobPrivateKey = Helper.loadPrivateKey("bob_DH_private_key.bin", "DH");
            byte[] encPackage = Helper.fromFiletoBinary(encryptedMessagePath);

            // Parse header outside benchmark window
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(encPackage));
            int ephPubKeyLen = dis.readInt();
            byte[] ephPubKeyBytes = new byte[ephPubKeyLen];
            dis.readFully(ephPubKeyBytes);
            int saltLen = dis.readInt();
            byte[] salt = new byte[saltLen];
            dis.readFully(salt);
            long ivAndCiphertextLen = dis.readLong();
            int headerSize = 4 + ephPubKeyLen + 4 + saltLen + 8;

            // Compute keys outside benchmark window
            PublicKey aliceEphemeralPublicKey = Helper.loadPublicKeyFromBytes(ephPubKeyBytes, "DH");
            byte[] sharedSecret = DHIES.computeSharedSecret(bobPrivateKey, aliceEphemeralPublicKey);
            DHIES.DerivedKeys derivedKeys = DHIES.deriveKeys(sharedSecret, salt);

            // Extract ivAndCiphertext and tag from in-memory package
            byte[] ivAndCiphertext = Arrays.copyOfRange(
                encPackage, headerSize, (int)(headerSize + ivAndCiphertextLen));
            byte[] expectedTag = Arrays.copyOfRange(
                encPackage, (int)(headerSize + ivAndCiphertextLen), encPackage.length);

            // Benchmark: verify HMAC + stream-decrypt in 8 MB chunks (no huge cipher.doFinal)
            ByteArrayOutputStream resultBaos = new ByteArrayOutputStream();
            BenchmarkHelper.BenchmarkResult benchmarkResult = BenchmarkHelper.measure(() -> {
                AES_DHIES.decryptToStreamVerified(ivAndCiphertext, resultBaos,
                    derivedKeys.getEncKey(), derivedKeys.getMacKey(), salt, expectedTag);
            });

            byte[] decryptedMessage = resultBaos.toByteArray();
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

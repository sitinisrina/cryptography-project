package main.DHIES_AES;

import main.Helper;
import main.BenchmarkHelper;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Scanner;

public class DHIESAliceasSender {

    // Kept for backward compat — used by old in-memory tests
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

    /**
     * Streaming encryption for large files — reads from inputPath, writes DHIES
     * streaming package to outputPath without loading the file into memory.
     *
     * Package format:
     *   [4-byte int: ephPubKeyLen] [ephPubKey]
     *   [4-byte int: saltLen] [salt]
     *   [8-byte long: ivAndCiphertextLen]
     *   [IV (16 B) + ciphertext]
     *   [32-byte HMAC-SHA256 tag]
     */
    public static void encryptFileToOutput(String inputPath, String outputPath) throws Exception {
        PublicKey bobPublicKey = Helper.loadPublicKey("bob_DH_public_key.bin", "DH");
        KeyPair aliceEphemeralKeyPair = DHIES.generateKeyPairFromPeerPublicKey(bobPublicKey);
        byte[] sharedSecret = DHIES.computeSharedSecret(aliceEphemeralKeyPair.getPrivate(), bobPublicKey);
        byte[] ephPubKey = aliceEphemeralKeyPair.getPublic().getEncoded();
        byte[] salt = DHIES.generateRandomSalt();
        DHIES.DerivedKeys derivedKeys = DHIES.deriveKeys(sharedSecret, salt);

        long plaintextLen = java.nio.file.Files.size(java.nio.file.Paths.get(inputPath));
        long ivAndCiphertextLen = AES_DHIES.IV_LENGTH + plaintextLen;

        try (DataOutputStream dos = new DataOutputStream(
                 new BufferedOutputStream(new FileOutputStream(outputPath)));
             BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputPath))) {
            dos.writeInt(ephPubKey.length);
            dos.write(ephPubKey);
            dos.writeInt(salt.length);
            dos.write(salt);
            dos.writeLong(ivAndCiphertextLen);
            byte[] tag = AES_DHIES.encryptToStreamWithMAC(
                bis, dos, derivedKeys.getEncKey(), derivedKeys.getMacKey(), salt);
            dos.write(tag);
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try {
            System.out.print("Masukkan path file yang ingin dikirim: ");
            String filePath = scanner.nextLine();

            PublicKey bobPublicKey = Helper.loadPublicKey("bob_DH_public_key.bin", "DH");
            byte[] fileContent = Helper.fromFiletoBinary(filePath);
            String originalHash = Helper.sha256(fileContent);

            // Pre-compute DH key material outside the benchmark window
            KeyPair aliceEphemeralKeyPair = DHIES.generateKeyPairFromPeerPublicKey(bobPublicKey);
            byte[] sharedSecret = DHIES.computeSharedSecret(aliceEphemeralKeyPair.getPrivate(), bobPublicKey);
            byte[] ephemeralPublicKeyBytes = aliceEphemeralKeyPair.getPublic().getEncoded();
            byte[] salt = DHIES.generateRandomSalt();
            DHIES.DerivedKeys derivedKeys = DHIES.deriveKeys(sharedSecret, salt);

            // Benchmark: stream-encrypt with HMAC in 8 MB chunks (no huge cipher.doFinal)
            ByteArrayOutputStream ciphertextBaos = new ByteArrayOutputStream();
            final byte[][] tagHolder = {null};

            BenchmarkHelper.BenchmarkResult benchmarkResult = BenchmarkHelper.measure(() -> {
                tagHolder[0] = AES_DHIES.encryptToStreamWithMAC(
                    new ByteArrayInputStream(fileContent), ciphertextBaos,
                    derivedKeys.getEncKey(), derivedKeys.getMacKey(), salt);
            });

            // Write streaming-format package to file
            byte[] ivAndCiphertext = ciphertextBaos.toByteArray();
            try (DataOutputStream dos = new DataOutputStream(
                     new BufferedOutputStream(new FileOutputStream("encrypted_DHIES_file.bin")))) {
                dos.writeInt(ephemeralPublicKeyBytes.length);
                dos.write(ephemeralPublicKeyBytes);
                dos.writeInt(salt.length);
                dos.write(salt);
                dos.writeLong(ivAndCiphertext.length);
                dos.write(ivAndCiphertext);
                dos.write(tagHolder[0]);
            }

            BenchmarkHelper.writeBenchmarkResult(
                    "alice_benchmark.txt",
                    "Alice",
                    benchmarkResult
            );

            System.out.println("Hash SHA-256 file asli          : " + originalHash);
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

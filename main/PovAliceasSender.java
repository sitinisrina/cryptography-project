import java.util.Scanner;

public class PovAliceasSender {
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Masukkan path file yang ingin dikirim: ");
        String filePath = scanner.nextLine();

        try {
            // 1. Generate RSA key pair
            var rsaKeyPair = HybridRSA_AES.generateRSAKeyPair();
            var publicKey = rsaKeyPair.getPublic();
            var privateKey = rsaKeyPair.getPrivate();

            // 2. Generate AES session key
            var sessionKey = HybridRSA_AES.generateSessionKey();

            // 3. Encrypt AES session key with RSA public key
            var encryptedSessionKey = HybridRSA_AES.encryptSessionKey(sessionKey, publicKey);

            // 4. Encrypt file content with AES session key
            var fileContent = Helper.fromFiletoBinary(filePath);
            var encryptedFileContent = HybridRSA_AES.encryptMessage(fileContent, sessionKey);

            // 5. Save encrypted data to files
            Helper.writeBinarytoFile(encryptedSessionKey, "encrypted_session_key.bin");
            Helper.writeBinarytoFile(encryptedFileContent, "encrypted_file.bin");

            System.out.println("File berhasil dienkripsi dan disimpan sebagai 'encrypted_session_key.bin' dan 'encrypted_file.bin'.");
            System.out.println("Public Key RSA (Base64): " + Helper.fromBinaryToBase64(publicKey.getEncoded()));

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            scanner.close();
        }

    }
}

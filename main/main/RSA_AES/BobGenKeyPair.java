package main.RSA_AES;

import main.Helper;
public class BobGenKeyPair {

    public static void main(String[] args) {
        try {
            var rsaKeyPair = HybridRSA_AES.generateRSAKeyPair();
            var bobPublicKey = rsaKeyPair.getPublic();
            var bobPrivateKey = rsaKeyPair.getPrivate();

            Helper.writeBinarytoFile(bobPublicKey.getEncoded(), "bob_public_key.bin");
            Helper.writeBinarytoFile(bobPrivateKey.getEncoded(), "bob_private_key.bin");

            System.out.println("Bob's RSA key pair generated and saved to 'bob_public_key.bin' and 'bob_private_key.bin'.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}

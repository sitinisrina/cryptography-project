package main.DHIES_AES;

import main.Helper;
import java.security.KeyPair;

public class BobDHKeyPair {
    public static void main(String[] args) {
        try {
            KeyPair bobKeyPair = DHIES.generateKeyPair();

            var bobPublicKey = bobKeyPair.getPublic();
            var bobPrivateKey = bobKeyPair.getPrivate();

            Helper.writeBinarytoFile(bobPublicKey.getEncoded(), "bob_DH_public_key.bin");
            Helper.writeBinarytoFile(bobPrivateKey.getEncoded(), "bob_DH_private_key.bin");

            System.out.println("Bob's DH key pair generated and saved.");
            System.out.println("Public key: bob_DH_public_key.bin");
            System.out.println("Private key: bob_DH_private_key.bin");

        } catch (Exception e) {
            System.err.println("Gagal membuat key pair DH Bob.");
            e.printStackTrace();
        }
    }
}
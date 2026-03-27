package main.DHIES_AES;

import main.Helper;
import java.security.KeyPair;

public class AliceDHKeyPair {
    public static void main(String[] args) {
        try {
            KeyPair aliceKeyPair = DHIES.generateKeyPair();

            var alicePublicKey = aliceKeyPair.getPublic();
            var alicePrivateKey = aliceKeyPair.getPrivate();

            Helper.writeBinarytoFile(alicePublicKey.getEncoded(), "alice_DH_public_key.bin");
            Helper.writeBinarytoFile(alicePrivateKey.getEncoded(), "alice_DH_private_key.bin");

            System.out.println("Alice's DH key pair generated and saved.");
            System.out.println("Public key: alice_DH_public_key.bin");
            System.out.println("Private key: alice_DH_private_key.bin");

        } catch (Exception e) {
            System.err.println("Gagal membuat key pair DH Alice.");
            e.printStackTrace();
        }
    }
}
package main.DHIES_AES;

import main.Helper;
import java.security.PublicKey;

public class BobDHKeyPair {
    public static void main(String[] args) {
        try {
            PublicKey alicePublicKey = Helper.loadPublicKey("alice_DH_public_key.bin", "DH");
            var bobKeyPair = DHIES.generateKeyPairFromPeerPublicKey(alicePublicKey);
            var bobPublicKey = bobKeyPair.getPublic();
            var bobPrivateKey = bobKeyPair.getPrivate();

            Helper.writeBinarytoFile(bobPublicKey.getEncoded(), "bob_DH_public_key.bin");
            Helper.writeBinarytoFile(bobPrivateKey.getEncoded(), "bob_DH_private_key.bin");

            System.out.println("Bob's DH key pair generated and saved to 'bob_DH_public_key.bin' and 'bob_DH_private_key.bin'.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

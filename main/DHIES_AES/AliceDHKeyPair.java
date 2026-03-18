package main.DHIES_AES;
import main.Helper;

public class AliceDHKeyPair {
    public static void main(String[] args) {
        try {
            var aliceKeyPair = HybridDHIES_AES.generateDHKeyPair();
            var alicePublicKey = aliceKeyPair.getPublic();
            var alicePrivateKey = aliceKeyPair.getPrivate();

            Helper.writeBinarytoFile(alicePublicKey.getEncoded(), "alice_DH_public_key.bin");
            Helper.writeBinarytoFile(alicePrivateKey.getEncoded(), "alice_DH_private_key.bin");

            System.out.println("Alice's DH key pair generated and saved to 'alice_DH_public_key.bin' and 'alice_DH_private_key.bin'.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

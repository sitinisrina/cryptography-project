package main.DHIES_AES;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class DHIES {
    
    private static final int KEY_SIZE = 2048;
    private static final String ALGORITHM = "DH";

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    public static KeyPair generateKeyPairFromPeerPublicKey(PublicKey peerPublicKey) throws Exception {
        DHParameterSpec dhParams = ((DHPublicKey) peerPublicKey).getParams();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
        keyGen.initialize(dhParams);

        return keyGen.generateKeyPair();
    }

    public static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance(ALGORITHM);
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        return keyAgree.generateSecret();
    }

    public static SecretKey deriveAESKey(byte[] sharedSecret) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(sharedSecret);
        byte[] aesKeyBytes = Arrays.copyOf(hash, 32); // AES-256 key length
        return new SecretKeySpec(aesKeyBytes, "AES");
    }

    public static void main(String[] args) {
        try {
        //Alice generates DH key pair
        KeyPair aliceKeyPair = generateKeyPair();
        System.out.println("Informasi dari Alice Keypair:");
        System.out.println("Public Key: " + aliceKeyPair.getPublic());
        System.out.println("Private Key: " + Arrays.toString(aliceKeyPair.getPrivate().getEncoded()));

        System.out.println("================================");

        //Bob generates DH key pair using Alice's public key
        KeyPair bobKeyPair = generateKeyPairFromPeerPublicKey(aliceKeyPair.getPublic());
        System.out.println("Informasi dari Bob Keypair:");
        System.out.println("Public Key: " + bobKeyPair.getPublic());
        System.out.println("Private Key: " + Arrays.toString(bobKeyPair.getPrivate().getEncoded()));

        System.out.println("================================");

        //Alice computes shared secret using Bob's public key
        byte[] aliceSharedSecret = computeSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());
        System.out.println("Alice's Shared Secret: " + Arrays.toString(aliceSharedSecret));

        //Bob computes shared secret using Alice's public key
        byte[] bobSharedSecret = computeSharedSecret(bobKeyPair.getPrivate(), aliceKeyPair.getPublic());
        System.out.println("Bob's Shared Secret: " + Arrays.toString(bobSharedSecret));

        System.out.println("================================");

        //Derive AES keys from shared secrets
        SecretKey aliceAESKey = deriveAESKey(aliceSharedSecret);
        System.out.println("Alice's Derived AES Key: " + Arrays.toString(aliceAESKey.getEncoded()));
        SecretKey bobAESKey = deriveAESKey(bobSharedSecret);
        System.out.println("Bob's Derived AES Key: " + Arrays.toString(bobAESKey.getEncoded()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

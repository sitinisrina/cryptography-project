package main.DHIES_AES;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class DHIES {
    
    private static final int KEY_SIZE = 2048;
    private static final String ALGORITHM = "DH";
    private static final String AES_ALGORITHM = "AES";
    private static final String HKDF_ALGORITHM = "HmacSHA256";
    private static final int AES_KEY_SIZE_BYTES = 32;
    private static final int HKDF_SALT_SIZE_BYTES = 16;

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    private static void validateDHPublicKey(PublicKey publicKey){
        if(publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        if (!(publicKey instanceof DHPublicKey)) {
            throw new IllegalArgumentException("Public key must be an instance of DHPublicKey");
        }
    }

    public static KeyPair generateKeyPairFromPeerPublicKey(PublicKey peerPublicKey) throws Exception {
        validateDHPublicKey(peerPublicKey);

        DHParameterSpec dhParams = ((DHPublicKey) peerPublicKey).getParams();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(dhParams);
        return keyGen.generateKeyPair();
    }

    public static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        validateDHPublicKey(publicKey);
        
        KeyAgreement keyAgree = KeyAgreement.getInstance(ALGORITHM);
        keyAgree.init(privateKey);
        keyAgree.doPhase(publicKey, true);
        return keyAgree.generateSecret();
    }

    public static byte[] generateRandomSalt() {
        byte[] salt = new byte[HKDF_SALT_SIZE_BYTES];
        new java.security.SecureRandom().nextBytes(salt);
        return salt;
    }

    public static SecretKey deriveAESKey(byte[] sharedSecret, byte[] salt) throws Exception {
        if (sharedSecret == null || sharedSecret.length == 0) {
            throw new IllegalArgumentException("Shared secret tidak boleh null atau kosong.");
        }

        if (salt == null || salt.length == 0) {
            throw new IllegalArgumentException("Salt tidak boleh null atau kosong.");
        }

        byte[] info = "DHIES-AES-v1".getBytes(StandardCharsets.UTF_8);

        byte[] prk = hkdfExtract(salt, sharedSecret);
        byte[] okm = hkdfExpand(prk, info, AES_KEY_SIZE_BYTES);

        return new SecretKeySpec(okm, AES_ALGORITHM);
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
        Mac mac = Mac.getInstance(HKDF_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(salt, HKDF_ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance(HKDF_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(prk, HKDF_ALGORITHM);

        byte[] output = new byte[length];
        byte[] previousBlock = new byte[0];

        int generatedLength = 0;
        int counter = 1;

        while (generatedLength < length) {
            mac.init(keySpec);

            mac.update(previousBlock);
            mac.update(info);
            mac.update((byte) counter);

            byte[] currentBlock = mac.doFinal();

            int bytesToCopy = Math.min(currentBlock.length, length - generatedLength);
            System.arraycopy(currentBlock, 0, output, generatedLength, bytesToCopy);

            generatedLength += bytesToCopy;
            previousBlock = currentBlock;
            counter++;
        }

        return output;
    }

    

    public static void main(String[] args) {
        try {
        //Alice generates DH key pair
        KeyPair aliceKeyPair = generateKeyPair();

        System.out.println("Informasi dari Alice Keypair:");
        System.out.println("Public Key: " + aliceKeyPair.getPublic());
        
        DHPublicKey alicePublicKey = (DHPublicKey) aliceKeyPair.getPublic();
        BigInteger p = alicePublicKey.getParams().getP();
        BigInteger g = alicePublicKey.getParams().getG();
        System.out.println("P: " + p);
        System.out.println("g: " + g);

        DHPrivateKey alicePrivateKey = (DHPrivateKey) aliceKeyPair.getPrivate();
        BigInteger a = alicePrivateKey.getX();
        System.out.println("Private key a: " + a);

        BigInteger publicKeyA = g.modPow(a, p);
        System.out.println("Public key A dari perhitungan: " + publicKeyA + " dan panjangnya: " + publicKeyA.toByteArray().length  + " bytes");
        System.out.println("Public key A dari object: " + alicePublicKey.getY() + " dan panjangnya: " + alicePublicKey.getY().toByteArray().length + " bytes");



        System.out.println("================================");

        // //Bob generates DH key pair using Alice's public key
        // KeyPair bobKeyPair = generateKeyPairFromPeerPublicKey(aliceKeyPair.getPublic());
        // System.out.println("Informasi dari Bob Keypair:");
        // System.out.println("Public Key: " + bobKeyPair.getPublic());
        // System.out.println("Private Key: " + Arrays.toString(bobKeyPair.getPrivate().getEncoded()));

        // System.out.println("================================");

        // //Alice computes shared secret using Bob's public key
        // byte[] aliceSharedSecret = computeSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());
        // System.out.println("Alice's Shared Secret: " + Arrays.toString(aliceSharedSecret));

        // //Bob computes shared secret using Alice's public key
        // byte[] bobSharedSecret = computeSharedSecret(bobKeyPair.getPrivate(), aliceKeyPair.getPublic());
        // System.out.println("Bob's Shared Secret: " + Arrays.toString(bobSharedSecret));

        // System.out.println("================================");

        // //Derive AES keys from shared secrets
        // SecretKey aliceAESKey = deriveAESKey(aliceSharedSecret);
        // System.out.println("Alice's Derived AES Key: " + Arrays.toString(aliceAESKey.getEncoded()));
        // SecretKey bobAESKey = deriveAESKey(bobSharedSecret);
        // System.out.println("Bob's Derived AES Key: " + Arrays.toString(bobAESKey.getEncoded()));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

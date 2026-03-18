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

public class DiffieHelman {
    
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
}

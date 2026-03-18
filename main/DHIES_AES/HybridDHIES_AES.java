package main.DHIES_AES;

import main.AES;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

/* 
1. alice generate keypair DH duluan
2. bob generate keypair DH dengan menggunakan public key alice
3. menghitung shared secret dari PubKey kedua party
4. menurunkan kunci sesi AES dari shared secret menggunakan KDF
5. enkripsi plaintext/message dengan kunci sesi AES yang telah diturunkan
6. dekripsi ciphertext dengan kunci sesi AES yang telah diturunkan
*/


public class HybridDHIES_AES {
    //1. Generate DH key pair
    public static KeyPair generateDHKeyPair() throws Exception {
        return DiffieHelman.generateKeyPair();
    }

    //2. Generate DH key pair from peer's public key
    public static KeyPair generateDHKeyPairFromPeerPublicKey(PublicKey peerPublicKey) throws Exception {
        return DiffieHelman.generateKeyPairFromPeerPublicKey(peerPublicKey);
    }

    //3. Compute shared secret
    public static byte[] computeSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        return DiffieHelman.computeSharedSecret(privateKey, publicKey);
    }

    //4. Derive AES session key from shared secret
    public static SecretKey deriveAESKey(byte[] sharedSecret) throws Exception {
        return DiffieHelman.deriveAESKey(sharedSecret);
    }

    //5. Encrypt message with AES session key
    public static byte[] encryptMessage(byte[] plaintext, SecretKey sessionKey) throws Exception {
        return AES.encrypt(plaintext, sessionKey);
    }

    //6. Decrypt message with AES session key
    public static byte[] decryptMessage(byte[] ciphertext, SecretKey sessionKey) throws Exception {
        return AES.decrypt(ciphertext, sessionKey);
    }

}
import javax.crypto.Cipher;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

public class RSA {
    
    private static final int KEY_SIZE = 2048;
    private static final String ALGORITHM = "RSA";
    private static final String CIPHER_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /**
     * Fungsi generateKeyPair mengggenarate kunci baru, PK dan SK.
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM); //getInstance() adalah concrete method yang generate public/private key
        keyGen.initialize(KEY_SIZE); //inisialisasi for certain key size.
        return keyGen.generateKeyPair();
    }

    /**
     * Encrypt plaintext using public key with OAEP padding
     */
    public static byte[] encrypt(byte[] plaintext, PublicKey publicKey) throws Exception {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plaintext);
    }

    /**
     * Decrypt ciphertext using private key with OAEP padding
     */
    public static byte[] decrypt(byte[] ciphertext, PrivateKey privateKey) throws Exception {
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext cannot be null or empty");
        }

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(ciphertext);
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = generateKeyPair();
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        System.out.println("Informasi dari private key:");
        BigInteger p = privateKey.getPrimeP();
        BigInteger q = privateKey.getPrimeQ();
        System.out.println("p = " + p + " (" + p.bitLength() + " bits)");
        System.out.println("q = " + q + " (" + q.bitLength() + " bits)");
        System.out.println("d = " + privateKey.getPrivateExponent() + " (" + privateKey.getPrivateExponent().bitLength() + " bits)");
        System.out.println("pq = " + p.multiply(q) + " (" + p.multiply(q).bitLength() + " bits)");
        System.out.println("n = " + privateKey.getModulus() + " (" + privateKey.getModulus().bitLength() + " bits)");
        System.out.println("------------------------------");

        System.out.println("Informasi dari public key:");
        System.out.println("e =" + publicKey.getPublicExponent() + " (" + publicKey.getPublicExponent().bitLength() + " bits)");
        System.out.println("-------------------------------");

        System.out.println("Informasi perhitungan based on charmicael function:");
        /*
        Carmichael function merupakan suatu fungsi dalam number theory, yang dalam RSA penggunaannya setara dengan totient function. Biasanya ditulis sbg lamda(n). Kegunaannya sama seperti totient, yakni untuk menghitung modular inverse dari e untuk mendapatkan d.
        */
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        System.out.println("phi = " + phi + " (" + phi.bitLength() + " bits)");

        BigInteger p1 = p.subtract(BigInteger.ONE);
        BigInteger q1 = q.subtract(BigInteger.ONE);

        BigInteger lambda = p1.multiply(q1).divide(p1.gcd(q1)); //(p1*q1)/gcd(p1,q1)

        System.out.println("ed mod lambda = " + publicKey.getPublicExponent().multiply(privateKey.getPrivateExponent()).mod(lambda));
        // BigInteger ed = privateKey.getPrivateExponent().multiply(publicKey.getPublicExponent());
        // System.out.println("ed mod phi = " + ed.mod(phi));
    }
}

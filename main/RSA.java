import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    
    private static final int KEY_SIZE = 2048;
    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int BLOCK_SIZE = KEY_SIZE / 8;
    private static final int MAX_MESSAGE_SIZE = BLOCK_SIZE - 2;

    public static class RSAPublicKey {
        private final BigInteger n;
        private final BigInteger e;

        public RSAPublicKey(BigInteger n, BigInteger e) {
            this.n = n;
            this.e = e;
        }

        public BigInteger getModulus() {
            return n;
        }

        public BigInteger getE() {
            return e;
        }
    }

    public static class RSAPrivateKey {
        private final BigInteger n;
        private final BigInteger d;

        public RSAPrivateKey(BigInteger n, BigInteger d) {
            this.n = n;
            this.d = d;
        }

        public BigInteger getModulus() {
            return n;
        }

        public BigInteger getD() {
            return d;
        }
    }

    public static class RSAKeyPair {
        private final RSAPublicKey publicKey;
        private final RSAPrivateKey privateKey;

        public RSAKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public RSAPublicKey getPublicKey() {
            return publicKey;
        }

        public RSAPrivateKey getPrivateKey() {
            return privateKey;
        }
    }

    public static RSAKeyPair generateKeyPair() {
        BigInteger p;
        BigInteger q;
        BigInteger n;
        BigInteger phi;
        BigInteger e = PUBLIC_EXPONENT;
        BigInteger d;

        while (true) {
            p = BigInteger.probablePrime(KEY_SIZE / 2, RANDOM);
            q = BigInteger.probablePrime(KEY_SIZE / 2, RANDOM);

            if (p.equals(q)) {
                continue;
            }

            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            if (e.gcd(phi).equals(BigInteger.ONE)) {
                d = e.modInverse(phi);
                break;
            }
        }

        return new RSAKeyPair(
            new RSAPublicKey(n, e),
            new RSAPrivateKey(n, d)
        );
    }

    public static byte[] encrypt(byte[] plaintext, RSAPublicKey publicKey) {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }

        if (plaintext.length > MAX_MESSAGE_SIZE) {
            throw new IllegalArgumentException("Message is too long for encryption");
        }

        BigInteger m = new BigInteger(1, plaintext);

        if (m.compareTo(publicKey.getModulus()) >= 0) {
            throw new IllegalArgumentException("Message integer must be smaller than modulus");
        }

        BigInteger c = m.modPow(publicKey.getE(), publicKey.getModulus());
        return c.toByteArray();
    }

    public static byte[] decrypt(byte[] ciphertext, RSAPrivateKey privateKey) {
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext cannot be null or empty");
        }

        BigInteger c = new BigInteger(1, ciphertext);
        BigInteger m = c.modPow(privateKey.getD(), privateKey.getModulus());

        byte[] decrypted = m.toByteArray();

        if (decrypted.length > 1 && decrypted[0] == 0) {
            byte[] temp = new byte[decrypted.length - 1];
            System.arraycopy(decrypted, 1, temp, 0, temp.length);
            return temp;
        }

        return decrypted;
    }
}
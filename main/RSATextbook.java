import java.math.BigInteger;
import java.security.SecureRandom;

public class RSATextbook {
    
    private static final int KEY_SIZE = 2048;
    private static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int BLOCK_SIZE = KEY_SIZE / 8;
    private static final int MAX_MESSAGE_SIZE = BLOCK_SIZE - 2; //angka 2 merepresentasikan pengurangan 2 byte untuk leading zero yang mungkin muncul saat mengonversi plaintext menjadi BigInteger, dan padding indicator agar plaintext tidak lebih besar dari RSA.

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
        // private final BigInteger n;
        private final BigInteger p;
        private final BigInteger q;
        private final BigInteger d;

        public RSAPrivateKey(BigInteger p, BigInteger q, BigInteger d) {
            this.p = p;
            this.q = q;
            this.d = d;
        }

        public BigInteger getModulus() {
            return p.multiply(q);
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
            /* 
            p dan q dipilih secara acak sebagai bilangan prima besar dengan panjang bitnya setengah dari ukuran kunci.
            BigInteger.probablePrime menggunakan kombinasi uji Miller-Rabin untuk menghasilkan bilangan prima yang besar dan acak, dan Sieve of Eratosthenes untuk memastikan keakuratannya. Dengan menggunakan metode ini, kita dapat dengan cepat menghasilkan bilangan prima yang cukup besar untuk RSA tanpa harus melakukan pemeriksaan primalitas yang rumit secara manual.
            */ 
            p = BigInteger.probablePrime(KEY_SIZE / 2, RANDOM);
            q = BigInteger.probablePrime(KEY_SIZE / 2, RANDOM);

            //memastikan p dan q tidak sama, karena jika sama, maka n akan menjadi kuadrat sempurna, yang mudah difaktorisasi
            if (p.equals(q)) {
                continue;
            }

            n = p.multiply(q);
            if (n.bitLength() != KEY_SIZE) {
                continue; // Regenerate if not exactly 2048 bits
            }
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); //menghitung totient phi(n)

            //memastikan e dan phi(n) coprime, sehingga e memiliki invers modulo phi(n)
            if (e.gcd(phi).equals(BigInteger.ONE)) {
                d = e.modInverse(phi);
                break;
            }
        }

        return new RSAKeyPair(
            new RSAPublicKey(n, e),
            new RSAPrivateKey(p, q, d)
        );
    }

    public static byte[] encrypt(byte[] plaintext, RSAPublicKey publicKey) {
        if (plaintext == null || plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be null or empty");
        }

        if (plaintext.length > MAX_MESSAGE_SIZE) {
            throw new IllegalArgumentException("Message is too long for encryption");
        }

        BigInteger m = new BigInteger(1, plaintext); //mengonversi array byte plaintext menjadi BigInteger, dengan tanda positif (1) untuk memastikan bahwa nilai yang dihasilkan selalu positif, bahkan jika byte pertama dari plaintext memiliki nilai negatif dalam representasi signed byte Java.

        if (m.compareTo(publicKey.getModulus()) >= 0) {
            throw new IllegalArgumentException("Message integer must be smaller than modulus");
        }

        BigInteger c = m.modPow(publicKey.getE(), publicKey.getModulus());
        return Helper.toFixedLength(c, BLOCK_SIZE); //mengembalikan BigInteger ciphertext sebagai array byte, yang dapat digunakan untuk penyimpanan.
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
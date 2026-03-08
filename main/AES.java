import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES {

    private static final String ALGORITHM = "AES/GCM/NoPadding"; // Algoritma yang digunakan untuk enkripsi, yaitu AES dalam mode GCM dengan padding NoPadding. AES (Advanced Encryption Standard) adalah algoritma kriptografi simetris yang umum digunakan, dan GCM (Galois/Counter Mode) adalah mode operasi yang menyediakan keamanan tambahan dengan menghasilkan tag autentikasi untuk memastikan integritas data. AES didefinisikan di dalam FIPS PUB 197, yang mendefinisikan hanya 3 panjang kunci.
    private static final int AES_KEY_SIZE = 256; // in bits, menentukan panjang kunci AES      
    private static final int IV_LENGTH = 12; // in bytes, IV adalah nilai unik yang digunakan untuk setiap enkripsi, biasanya 12 bytes untuk GCM, karena 4 bytes digunakan untuk counter GCM. 
    private static final int GCM_TAG_LENGTH = 128; // in bits, ukuran tag autentikasi GCM, biasanya 128 bits (16 bytes)  

    /*
    SecretKey generateAESKey() adalah metode yang menghasilkan kunci AES dengan panjang yang ditentukan oleh AES_KEY_SIZE. Metode ini menggunakan KeyGenerator untuk membuat kunci AES yang aman. Kunci ini akan digunakan dalam proses enkripsi dan dekripsi data menggunakan algoritma AES-GCM.

    SecretKey adalah interface dalam paket javax.crypto.

    KeyGenerator adalah kelas yang digunakan untuk menghasilkan kunci kriptografi.

    keyGen.init menginisialisasi generator kunci dengan panjang kunci yang ditentukan (dalam bit).
    */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    public static byte[] generateIV() {
        /* 
        Membuat array kosong untuk IV dengan panjang yang ditentukan oleh IV_LENGTH (12 bytes). IV (Initialization Vector) adalah nilai unik yang digunakan untuk setiap enkripsi, dan biasanya memiliki panjang 12 bytes untuk algoritma GCM.
        Mengisi array IV dengan nilai acak menggunakan SecureRandom. IV harus unik untuk setiap enkripsi untuk memastikan keamanan. Dengan menggunakan SecureRandom, kita dapat menghasilkan IV yang tidak dapat diprediksi, sehingga meningkatkan keamanan enkripsi AES-GCM.
        */
        byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    //ambil plaintext → bytes → bikin IV → init cipher AES/GCM → doFinal() → gabung IV + ciphertext(+tag)
    public static byte[] encrypt(byte[] plaintextBytes, SecretKey key) {
        try {
            byte[] iv = generateIV();

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv)); // Inisialisasi cipher untuk mode enkripsi dengan parameter key dan parameter GCM untuk ukuran tag

            byte[] ciphertextWithTag = cipher.doFinal(plaintextBytes); //ciphertext disini sudah termasuk tag autentikasi di 16 byte terakhir

            byte[] out = new byte[iv.length + ciphertextWithTag.length];
            System.arraycopy(iv, 0, out, 0, iv.length); //arraycopy(sumber, posisi_awal_sumber, tujuan, posisi_awal_tujuan, jumlah_yang_disalin)
            System.arraycopy(ciphertextWithTag, 0, out, iv.length, ciphertextWithTag.length);
            return out;

        } catch (Exception e) {
            throw new RuntimeException("Encrypt AES-GCM gagal", e);
        }  
    }    

    public static byte[] decrypt(byte[] ivAndCiphertext, SecretKey key) {
        int tagLengthBytes = GCM_TAG_LENGTH / 8;

        if (ivAndCiphertext == null || ivAndCiphertext.length < IV_LENGTH + tagLengthBytes) {
            throw new IllegalArgumentException(
                "Data terenkripsi tidak valid atau terlalu pendek."
            );
        }

        try {
            byte[] iv = Arrays.copyOfRange(ivAndCiphertext, 0, IV_LENGTH);
            byte[] ciphertextWithTag = Arrays.copyOfRange(ivAndCiphertext, IV_LENGTH, ivAndCiphertext.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            return cipher.doFinal(ciphertextWithTag);

        } catch (AEADBadTagException e) {
            throw new RuntimeException("Authentication tag tidak valid.", e);
        } catch (Exception e) {
            throw new RuntimeException("Gagal melakukan dekripsi AES-GCM", e);
        }
    }
}
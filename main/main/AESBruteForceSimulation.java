package main;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.Locale;

/**
 *  AESBruteForceSimulation.java
 *  Simulasi Estimasi Waktu Brute Force pada AES
 *
 *  Konsep:
 *  - Brute force menyerang KUNCI, bukan mode operasi (GCM/CTR/dll)
 *  - Keyspace = 2^n  (n = panjang kunci dalam bit)
 *  - T_worst = Keyspace / Speed
 *  - T_avg   = Keyspace / (2 * Speed)   ← rata-rata: temukan di tengah
 *
 *  Relevansi ke proyek ini:
 *  - RSA-AES  menggunakan AES-256-GCM  → Keyspace = 2^256
 *  - DHIES-AES menggunakan AES-256-CTR → Keyspace = 2^256 
 *
 *  Mode GCM/CTR TIDAK mempengaruhi ukuran keyspace,
 *  sehingga estimasi brute force untuk keduanya IDENTIK.
 * ============================================================
 */
public class AESBruteForceSimulation {

    // Konstanta Fisika & Waktu
    private static final BigDecimal SECONDS_PER_MINUTE  = BigDecimal.valueOf(60);
    private static final BigDecimal SECONDS_PER_HOUR    = BigDecimal.valueOf(3600);
    private static final BigDecimal SECONDS_PER_DAY     = BigDecimal.valueOf(86400);
    private static final BigDecimal SECONDS_PER_YEAR    = BigDecimal.valueOf(31536000);

    // Umur alam semesta ≈ 13.8 miliar tahun = 4.354 × 10^17 detik
    private static final BigDecimal AGE_OF_UNIVERSE_SECONDS = new BigDecimal("4.354e17");

    // Definisi Varian AES
    private static final int[] AES_KEY_SIZES = { 128, 192, 256 };

    // Jumlah ronde untuk setiap varian AES (tidak mempengaruhi keyspace)
    private static final int AES_128_ROUNDS = 10;
    private static final int AES_192_ROUNDS = 12;
    private static final int AES_256_ROUNDS = 14;

    // Nilai ini adalah estimasi umum berdasarkan literatur kriptografi
    private static final Object[][] HARDWARE_PROFILES = {
        // { nama,                        keys per detik (BigDecimal) }
        { "CPU Modern (1 core)",          new BigDecimal("1e8")  },
        { "GPU RTX 4090",                 new BigDecimal("1e10") },
        { "FPGA Khusus",                  new BigDecimal("1e11") },
        { "Superkomputer",                new BigDecimal("1e15") },
        { "Semua Komputer di Bumi (~)",   new BigDecimal("1e23") },
    };

    // Relevansi Proyek
    private static final String[][] PROJECT_AES_INFO = {
        { "RSA-AES",   "AES-256-GCM", "256" },
        { "DHIES-AES", "AES-256-CTR", "256" },
    };

    public static void main(String[] args) {
        printHeader();
        printProjectContext();
        printSeparator('=', 72);

        // Tampilkan simulasi 
        for (int keySize : AES_KEY_SIZES) {
            simulateForKeySize(keySize);
        }

        printFooter();
    }

    
    //  SIMULASI PER UKURAN KUNCI
    private static void simulateForKeySize(int keyBits) {
        BigInteger keyspace   = BigInteger.TWO.pow(keyBits);
        int        rounds     = aesRounds(keyBits);

        // Faktor koreksi kecepatan: basis AES-128 (10 round) dibanding varian ini
        // Contoh: AES-256 (14 round) → faktor = 10/14 → lebih lambat
        BigDecimal roundFactor = BigDecimal.valueOf(AES_128_ROUNDS)
                                           .divide(BigDecimal.valueOf(rounds), MathContext.DECIMAL64);

        System.out.printf("%n  ┌─────────────────────────────────────────────────────────────┐%n");
        System.out.printf("  │  AES-%d%-54s│%n", keyBits, "");
        System.out.printf("  ├─────────────────────────────────────────────────────────────┤%n");
        System.out.printf("  │  Panjang Kunci  : %d bit%n", keyBits);
        System.out.printf("  │  Jumlah Round   : %d round%n", rounds);
        System.out.printf("  │  Keyspace (2^%d): %s%n", keyBits, formatScientific(new BigDecimal(keyspace)));
        System.out.printf("  │  Faktor koreksi : AES-128 rounds / AES-%d rounds = 10/%d ≈ %.3f%n",
                keyBits, rounds, roundFactor.doubleValue());
        System.out.printf("  └─────────────────────────────────────────────────────────────┘%n");

        System.out.printf("  %-30s  %-16s  %-22s  %-22s%n",
                "Hardware (Attacker)", "Speed (keys/s)",
                "Worst Case (T_worst)", "Average Case (T_avg)");
        printSeparator('-', 95);

        for (Object[] hw : HARDWARE_PROFILES) {
            String     hwName    = (String)     hw[0];
            BigDecimal baseSpeed = (BigDecimal) hw[1];

            // Kecepatan efektif = kecepatan basis × faktor koreksi round
            BigDecimal effectiveSpeed = baseSpeed.multiply(roundFactor, MathContext.DECIMAL64);
            BigInteger speedInt       = effectiveSpeed.toBigInteger();

            BigDecimal tWorst = calculateTimeSeconds(keyspace, speedInt, false);
            BigDecimal tAvg   = calculateTimeSeconds(keyspace, speedInt, true);

            System.out.printf("  %-30s  %-16s  %-22s  %-22s%n",
                    hwName,
                    formatScientific(effectiveSpeed),
                    formatTime(tWorst),
                    formatTime(tAvg));
        }

        // Perbandingan dengan umur alam semesta (menggunakan T_avg GPU RTX 4090)
        BigDecimal gpuBase     = (BigDecimal) HARDWARE_PROFILES[1][1];
        BigDecimal gpuEffSpeed = gpuBase.multiply(roundFactor, MathContext.DECIMAL64);
        BigDecimal tGpuAvg     = calculateTimeSeconds(keyspace, gpuEffSpeed.toBigInteger(), true);
        BigDecimal ratio       = tGpuAvg.divide(AGE_OF_UNIVERSE_SECONDS, MathContext.DECIMAL64);

        System.out.println();
        System.out.printf("  Dengan GPU RTX 4090 (avg, AES-%d, %d round), waktu brute force:%n",
                keyBits, rounds);
        if (ratio.compareTo(BigDecimal.ONE) < 0) {
            System.out.printf("  ≈ %s x umur alam semesta (SANGAT SINGKAT — TIDAK AMAN!)%n",
                    formatScientific(ratio));
        } else {
            System.out.printf("  ≈ %s x umur alam semesta%n", formatScientific(ratio));
        }
        printSeparator('=', 72);
    }

    //  HELPER: JUMLAH ROUND AES
    private static int aesRounds(int keyBits) {
        switch (keyBits) {
            case 128: return AES_128_ROUNDS;
            case 192: return AES_192_ROUNDS;
            case 256: return AES_256_ROUNDS;
            default:  throw new IllegalArgumentException("Ukuran kunci AES tidak valid: " + keyBits);
        }
    }

    public static BigDecimal calculateTimeSeconds(BigInteger keyspace, BigInteger speed, boolean average) {
        BigDecimal ks = new BigDecimal(keyspace);
        BigDecimal sp = new BigDecimal(speed);
        if (average) {
            sp = sp.multiply(BigDecimal.valueOf(2));
        }
        return ks.divide(sp, MathContext.DECIMAL64);
    }

    private static String formatTime(BigDecimal seconds) {
        if (seconds.compareTo(SECONDS_PER_MINUTE) < 0) {
            return String.format(Locale.US, "%.2f detik", seconds.doubleValue());
        }
        if (seconds.compareTo(SECONDS_PER_HOUR) < 0) {
            return String.format(Locale.US, "%.2f menit",
                    seconds.divide(SECONDS_PER_MINUTE, MathContext.DECIMAL64).doubleValue());
        }
        if (seconds.compareTo(SECONDS_PER_DAY) < 0) {
            return String.format(Locale.US, "%.2f jam",
                    seconds.divide(SECONDS_PER_HOUR, MathContext.DECIMAL64).doubleValue());
        }
        if (seconds.compareTo(SECONDS_PER_YEAR) < 0) {
            return String.format(Locale.US, "%.2f hari",
                    seconds.divide(SECONDS_PER_DAY, MathContext.DECIMAL64).doubleValue());
        }
        BigDecimal years = seconds.divide(SECONDS_PER_YEAR, MathContext.DECIMAL64);
        return formatScientific(years) + " tahun";
    }

    /**
     * Memformat BigDecimal ke notasi ilmiah (misal: 1.836e+59).
     *
     * Menggunakan Locale.US agar desimal selalu titik.
     * Hanya menggunakan doubleValue() — dead-code toEngineeringString() dihapus.
     * Jika nilai melebihi range double (> ~1.8e308), tampilkan sebagai plain string.
     */
    private static String formatScientific(BigDecimal value) {
        if (value.compareTo(BigDecimal.ZERO) == 0) return "0";
        double d = value.doubleValue();
        if (!Double.isInfinite(d) && !Double.isNaN(d) && d > 0) {
            return String.format(Locale.US, "%.3e", d);
        }
        // Fallback untuk nilai di luar jangkauan double (sangat tidak mungkin di sini)
        return value.round(new MathContext(4, RoundingMode.HALF_UP)).toString();
    }

    //  DISPLAY HELPERS
    private static void printHeader() {
        System.out.println();
        printSeparator('=', 72);
        System.out.println("   SIMULASI ESTIMASI BRUTE FORCE - AES (128 / 192 / 256 bit)");
        System.out.println("   Berdasarkan: Keyspace = 2^n  |  T = Keyspace / Speed");
        printSeparator('=', 72);
    }

    private static void printProjectContext() {
        System.out.println();
        System.out.println("  RELEVANSI KE PROYEK:");
        System.out.printf("  %-15s  %-20s  %-10s  %s%n",
                "Proyek", "Mode AES", "Key Size", "Keyspace");
        printSeparator('-', 72);
        for (String[] info : PROJECT_AES_INFO) {
            BigInteger ks = BigInteger.TWO.pow(Integer.parseInt(info[2]));
            System.out.printf("  %-15s  %-20s  %-10s  %s%n",
                    info[0], info[1], info[2] + " bit",
                    formatScientific(new BigDecimal(ks)));
        }
        System.out.println();
        System.out.println("Kedua proyek menggunakan AES-256 sehingga estimasi brute force IDENTIK.");
        System.out.println();
    }

    private static void printFooter() {
        System.out.println();
        System.out.println("KESIMPULAN:");
        System.out.println("Serangan brute force pada AES secara praktis TIDAK MUNGKIN dilakukan dengan \nteknologi komputasi yang ada maupun yang diprediksi dalam waktu dekat.");
        System.out.println();
        printSeparator('=', 72);
    }

    private static void printSeparator(char ch, int length) {
        System.out.println("  " + String.valueOf(ch).repeat(length));
    }
}
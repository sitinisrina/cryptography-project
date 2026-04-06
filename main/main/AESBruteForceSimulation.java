package main;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;

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

    // Nilai ini adalah estimasi umum berdasarkan literatur kriptografi
    private static final Object[][] HARDWARE_PROFILES = {
        // { nama,                        keys per detik (BigInteger) }
        { "CPU Modern (1 core)",          new BigInteger("100000000")           },  // 10^8
        { "GPU RTX 4090",                 new BigInteger("10000000000")         },  // 10^10
        { "FPGA Khusus",                  new BigInteger("100000000000")        },  // 10^11
        { "Superkomputer",                new BigInteger("1000000000000000")    },  // 10^15
        { "Semua Komputer di Bumi (~)",   new BigInteger("100000000000000000000000") }, // 10^23
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

    // ════════════════════════════════════════════════════════════════════════
    //  SIMULASI PER UKURAN KUNCI
    // ════════════════════════════════════════════════════════════════════════
    private static void simulateForKeySize(int keyBits) {
        BigInteger keyspace = BigInteger.TWO.pow(keyBits);

        System.out.printf("%n  ┌─────────────────────────────────────────────────────────────┐%n");
        System.out.printf("  │  AES-%d                                                      │%n", keyBits);
        System.out.printf("  ├─────────────────────────────────────────────────────────────┤%n");
        System.out.printf("  │  Panjang Kunci  : %d bit%n", keyBits);
        System.out.printf("  │  Keyspace (2^%d): %s%n", keyBits, formatScientific(new BigDecimal(keyspace)));
        System.out.printf("  └─────────────────────────────────────────────────────────────┘%n");

        System.out.printf("  %-30s  %-22s  %-22s%n",
                "Hardware (Attacker)",
                "Worst Case (T_worst)",
                "Average Case (T_avg)");
        printSeparator('-', 80);

        for (Object[] hw : HARDWARE_PROFILES) {
            String hwName      = (String) hw[0];
            BigInteger speed   = (BigInteger) hw[1];

            BigDecimal tWorst  = calculateTimeSeconds(keyspace, speed, false);
            BigDecimal tAvg    = calculateTimeSeconds(keyspace, speed, true);

            String worstStr    = formatTime(tWorst);
            String avgStr      = formatTime(tAvg);

            System.out.printf("  %-30s  %-22s  %-22s%n", hwName, worstStr, avgStr);
        }

        // Perbandingan dengan umur alam semesta (pakai worst case GPU)
        BigInteger gpuSpeed  = (BigInteger) HARDWARE_PROFILES[1][1]; // RTX 4090
        BigDecimal tGpuAvg   = calculateTimeSeconds(keyspace, gpuSpeed, true);
        BigDecimal ratioToUniverse = tGpuAvg.divide(AGE_OF_UNIVERSE_SECONDS, MathContext.DECIMAL64);

        System.out.println();
        System.out.printf("Dengan GPU RTX 4090 (avg), waktu brute force AES-%d%n", keyBits);
        if (ratioToUniverse.compareTo(BigDecimal.ONE) < 0) {
            System.out.printf(" ≈ %.2e x umur alam semesta (sangat singkat — TIDAK AMAN!)%n",
                    ratioToUniverse.doubleValue());
        } else {
            System.out.printf(" ≈ %s x umur alam semesta%n", formatScientific(ratioToUniverse));
        }
        printSeparator('=', 72);
    }

    /**
     * Hitung estimasi waktu (dalam detik) untuk brute force.
     *
     * @param keyspace  Total kemungkinan kunci = 2^n
     * @param speed     Kecepatan attacker dalam keys/detik
     * @param average   true  → T_avg   = keyspace / (2 × speed)
     *                  false → T_worst = keyspace / speed
     * @return Estimasi waktu dalam detik (BigDecimal)
     */
    public static BigDecimal calculateTimeSeconds(BigInteger keyspace, BigInteger speed, boolean average) {
        BigDecimal ks = new BigDecimal(keyspace);
        BigDecimal sp = new BigDecimal(speed);
        if (average) {
            sp = sp.multiply(BigDecimal.valueOf(2));
        }
        return ks.divide(sp, MathContext.DECIMAL64);
    }

    /**
     * Format waktu dalam detik ke satuan yang paling bermakna.
     * Jika sangat besar, tampilkan dalam tahun dengan notasi ilmiah.
     */
    private static String formatTime(BigDecimal seconds) {
        // Bandingkan dengan 1 menit
        if (seconds.compareTo(SECONDS_PER_MINUTE) < 0) {
            return String.format("%.2f detik", seconds.doubleValue());
        }
        // Bandingkan dengan 1 jam
        if (seconds.compareTo(SECONDS_PER_HOUR) < 0) {
            return String.format("%.2f menit", seconds.divide(SECONDS_PER_MINUTE, MathContext.DECIMAL64).doubleValue());
        }
        // Bandingkan dengan 1 hari
        if (seconds.compareTo(SECONDS_PER_DAY) < 0) {
            return String.format("%.2f jam", seconds.divide(SECONDS_PER_HOUR, MathContext.DECIMAL64).doubleValue());
        }
        // Bandingkan dengan 1 tahun
        if (seconds.compareTo(SECONDS_PER_YEAR) < 0) {
            return String.format("%.2f hari", seconds.divide(SECONDS_PER_DAY, MathContext.DECIMAL64).doubleValue());
        }
        // Tampilkan dalam tahun (notasi ilmiah)
        BigDecimal years = seconds.divide(SECONDS_PER_YEAR, MathContext.DECIMAL64);
        return formatScientific(years) + " tahun";
    }

    /** Format BigDecimal ke notasi ilmiah: x.xxe+yy */
    private static String formatScientific(BigDecimal value) {
        if (value.compareTo(BigDecimal.ZERO) == 0) return "0";
        // Gunakan format engineering/scientific
        BigDecimal normalized = value.round(new MathContext(4, RoundingMode.HALF_UP));
        // Konversi ke string lalu format ulang sebagai scientific
        String plain = normalized.toEngineeringString();
        // Fallback: gunakan format double jika nilai masih dalam range
        double d = value.doubleValue();
        if (!Double.isInfinite(d) && !Double.isNaN(d) && d > 0) {
            return String.format("%.3e", d);
        }
        return plain;
    }

    // ════════════════════════════════════════════════════════════════════════
    //  DISPLAY HELPERS
    // ════════════════════════════════════════════════════════════════════════
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
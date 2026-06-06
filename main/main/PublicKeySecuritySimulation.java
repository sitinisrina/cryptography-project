package main;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.math.RoundingMode;
import java.util.Locale;

/**
 *  PublicKeySecuritySimulation.java
 *  Simulasi Keamanan Lapisan Kunci Publik: RSA-2048 dan Diffie-Hellman 2048-bit
 *
 *  Konsep Utama - Equivalent Security Strength (ESS):
 *  -----------------------------------------------------
 *  Algoritma kunci publik (RSA, DH) TIDAK diserang dengan mencoba semua
 *  kemungkinan kunci privat secara langsung (brute force ekshaustif).
 *  Serangannya adalah serangan matematis (faktorisasi untuk RSA,
 *  logaritma diskrit untuk DH), yang jauh lebih efisien dari brute force.
 *
 *  Oleh karena itu, ketahanan RSA dan DH diukur melalui
 *  Equivalent Security Strength (ESS), yaitu berapa bit kunci simetris
 *  yang setara secara kesulitan komputasi.
 *
 *  Sumber: NIST Special Publication 800-57 Part 1 Rev. 5, Tabel 2.
 *    - RSA-2048  -> ESS = 112 bit
 *    - DH-2048   -> ESS = 112 bit
 *    - AES-256   -> ESS = 256 bit  (untuk referensi perbandingan)
 *
 *  Formula konversi ESS -> estimasi waktu serangan:
 *  -----------------------------------------------------
 *  ESS menyatakan "setara dengan brute force kunci simetris ESS-bit".
 *  Dengan demikian, estimasi waktu dapat dihitung seperti brute force AES:
 *
 *    Effective Keyspace = 2^ESS
 *    T_worst = 2^ESS / speed
 *    T_avg   = 2^ESS / (2 * speed)
 *
 *  Relevansi ke proyek skema dua lapis:
 *  -----------------------------------------------------
 *  Keamanan skema KESELURUHAN = min(keamanan tiap lapisan)
 *  Penyerang hanya perlu membobol SATU lapisan (yang terlemah).
 *  Lapisan AES-256 (ESS 256-bit) jauh lebih kuat dari RSA/DH (ESS 112-bit).
 *  -> Bottleneck keamanan ada pada lapisan kunci publik (112-bit).
 *
 *  Referensi:
 *  [1] NIST SP 800-57 Part 1 Rev. 5 (2020), Tabel 2
 *  [2] Lenstra & Verheul, "Selecting Cryptographic Key Sizes", 2001
 *  [3] Schneier, "Applied Cryptography", 2nd ed.
 * ============================================================
 */
public class PublicKeySecuritySimulation {

    // ------------------------------------------------------------------------
    //  KONSTANTA WAKTU & FISIKA
    // ------------------------------------------------------------------------
    private static final BigDecimal SECONDS_PER_YEAR       = BigDecimal.valueOf(31_536_000);
    private static final BigDecimal AGE_OF_UNIVERSE_YEARS  = new BigDecimal("1.38e10");   // 13.8 miliar tahun
    private static final BigDecimal AGE_OF_UNIVERSE_SECONDS= new BigDecimal("4.354e17");

    // ------------------------------------------------------------------------
    //  PROFIL ALGORITMA KUNCI PUBLIK
    //  ESS (bit) bersumber dari NIST SP 800-57 Part 1 Rev. 5, Tabel 2
    // ------------------------------------------------------------------------
    private static final Object[][] PUBLIC_KEY_PROFILES = {
        // { nama algoritma,     ukuran parameter,  ESS (bit),  jenis serangan terbaik }
        { "RSA-2048",            2048,              112,        "Integer Factorization (GNFS)"        },
        { "Diffie-Hellman 2048", 2048,              112,        "Discrete Logarithm (Index Calculus)" },
    };

    // Untuk referensi perbandingan lapisan simetris
    private static final Object[][] SYMMETRIC_REFERENCE = {
        { "AES-256",  256,  256,  "Exhaustive Key Search" },
    };

    // ------------------------------------------------------------------------
    //  PROFIL HARDWARE (kecepatan dalam keys/s, basis AES-128)
    //  Digunakan untuk semua perhitungan ESS -> waktu ekuivalen
    //  Sumber: OpenSSL benchmark, CUDA AES, Schneier Applied Cryptography
    // ------------------------------------------------------------------------
    private static final Object[][] HARDWARE_PROFILES = {
        { "CPU Modern (1 core)",        new BigDecimal("1e8")  },
        { "GPU RTX 4090",               new BigDecimal("1e10") },
    };

    // ------------------------------------------------------------------------
    //  RELEVANSI PROYEK - skema dua lapis
    // ------------------------------------------------------------------------
    private static final String[][] SCHEME_LAYERS = {
        // { nama skema,     lapisan publik,          ESS publik,  lapisan simetris,  ESS simetris }
        { "RSA-AES",         "RSA-2048",              "112",       "AES-256-GCM",     "256" },
        { "DHIES-AES",       "DH-2048",               "112",       "AES-256-CTR",     "256" },
    };

    // ========================================================================
    //  MAIN
    // ========================================================================
    public static void main(String[] args) {
        printHeader();
        printEssConcept();
        printSeparator('=', 76);

        // 1. Simulasi tiap algoritma kunci publik
        for (Object[] profile : PUBLIC_KEY_PROFILES) {
            simulatePublicKeyAlgorithm(profile);
        }

        // 2. Tabel perbandingan semua lapisan (AES-128/192/256 + RSA + DH)
        printLayerComparisonTable();

        // 3. Analisis bottleneck per skema
        printSchemeBottleneckAnalysis();

        printFooter();
    }

    // ========================================================================
    //  SIMULASI PER ALGORITMA KUNCI PUBLIK
    // ========================================================================
    private static void simulatePublicKeyAlgorithm(Object[] profile) {
        String algoName   = (String)  profile[0];
        int    paramBits  = (int)     profile[1];
        int    essBits    = (int)     profile[2];
        String attackName = (String)  profile[3];

        // Effective keyspace = 2^ESS  (serangan terbaik setara dengan ini)
        BigInteger essKeyspace = BigInteger.TWO.pow(essBits);

        System.out.printf("%n  +-----------------------------------------------------------------+%n");
        System.out.printf("  |  %s%-63s|%n", algoName, "");
        System.out.printf("  +-----------------------------------------------------------------+%n");
        System.out.printf("  |  Ukuran parameter     : %d bit%n", paramBits);
        System.out.printf("  |  Serangan terbaik     : %s%n", attackName);
        System.out.printf("  |  Equiv. Security (ESS): %d bit  [NIST SP 800-57 Part 1 Rev.5]%n", essBits);
        System.out.printf("  |  Effective Keyspace   : 2^%d ~ %s%n",
                essBits, formatScientific(new BigDecimal(essKeyspace)));
        System.out.printf("  |%n");
        System.out.printf("  |  Interpretasi: membobol %s setara kesulitannya%n", algoName);
        System.out.printf("  |  dengan brute force kunci simetris %d-bit.%n", essBits);
        System.out.printf("  +-----------------------------------------------------------------+%n");

        System.out.printf("  %-30s  %-22s  %-22s%n",
                "Hardware (Attacker)", "Worst Case (T_worst)", "Average Case (T_avg)");
        printSeparator('-', 80);

        for (Object[] hw : HARDWARE_PROFILES) {
            String     hwName = (String)     hw[0];
            BigDecimal speed  = (BigDecimal) hw[1];

            BigDecimal tWorst = calculateTimeYears(essKeyspace, speed, false);
            BigDecimal tAvg   = calculateTimeYears(essKeyspace, speed, true);

            System.out.printf("  %-30s  %-22s  %-22s%n",
                    hwName,
                    formatTime(tWorst),
                    formatTime(tAvg));
        }

        // Perbandingan dengan umur alam semesta (GPU RTX 4090)
        BigDecimal gpuSpeed = (BigDecimal) HARDWARE_PROFILES[1][1];
        BigDecimal tGpuAvg  = calculateTimeYears(essKeyspace, gpuSpeed, true);
        BigDecimal ratio    = tGpuAvg.divide(AGE_OF_UNIVERSE_YEARS, MathContext.DECIMAL64);

        System.out.println();
        System.out.printf("  Dengan GPU RTX 4090 (avg), membobol %s:%n", algoName);
        if (ratio.compareTo(BigDecimal.ONE) < 0) {
            System.out.printf("  ~ %s x umur alam semesta  <- SANGAT SINGKAT, TIDAK AMAN!%n",
                    formatScientific(ratio));
        } else {
            System.out.printf("  ~ %s x umur alam semesta%n", formatScientific(ratio));
        }
        printSeparator('=', 76);
    }

    // ========================================================================
    //  TABEL PERBANDINGAN SEMUA LAPISAN
    // ========================================================================
    private static void printLayerComparisonTable() {
        System.out.println();
        System.out.println("  PERBANDINGAN ESS DAN ESTIMASI WAKTU SERANGAN - SEMUA LAPISAN");
        System.out.println("  (Penyerang: GPU RTX 4090, T_avg)");
        printSeparator('-', 76);
        System.out.printf("  %-24s  %-12s  %-10s  %-24s%n",
                "Algoritma", "Param (bit)", "ESS (bit)", "T_avg GPU RTX 4090");
        printSeparator('-', 76);

        // Lapisan simetris (referensi)
        for (Object[] sym : SYMMETRIC_REFERENCE) {
            String     name    = (String) sym[0];
            int        ess     = (int)    sym[2];
            BigInteger ks      = BigInteger.TWO.pow(ess);
            BigDecimal gpuSpd  = (BigDecimal) HARDWARE_PROFILES[1][1];
            BigDecimal tAvg    = calculateTimeYears(ks, gpuSpd, true);
            System.out.printf("  %-24s  %-12s  %-10d  %-24s%n",
                    name, sym[1] + " bit", ess, formatTime(tAvg));
        }

        printSeparator('-', 76);

        // Lapisan kunci publik
        for (Object[] pub : PUBLIC_KEY_PROFILES) {
            String     name   = (String) pub[0];
            int        param  = (int)    pub[1];
            int        ess    = (int)    pub[2];
            BigInteger ks     = BigInteger.TWO.pow(ess);
            BigDecimal gpuSpd = (BigDecimal) HARDWARE_PROFILES[1][1];
            BigDecimal tAvg   = calculateTimeYears(ks, gpuSpd, true);
            System.out.printf("  %-24s  %-12s  %-10d  %-24s %n",
                    name, param + " bit", ess, formatTime(tAvg));
        }

        printSeparator('=', 76);
        System.out.println();
        System.out.println("  CATATAN: ESS kunci publik jauh lebih rendah dari panjang parameternya.");
        System.out.println("  RSA-2048 bukan berarti aman seperti AES-2048. ESS-nya hanya 112 bit.");
        System.out.println("  Ini karena serangan matematis (GNFS/Index Calculus) jauh lebih efisien");
        System.out.println("  daripada brute force murni.");
        System.out.println();
        printSeparator('=', 76);
    }

    // ========================================================================
    //  ANALISIS BOTTLENECK PER SKEMA DUA LAPIS
    // ========================================================================
    private static void printSchemeBottleneckAnalysis() {
        System.out.println();
        System.out.println("  ANALISIS BOTTLENECK KEAMANAN - SKEMA DUA LAPIS");
        printSeparator('-', 76);
        System.out.println();
        System.out.println("  Prinsip: keamanan skema hybrid = keamanan lapisan TERLEMAH.");
        System.out.println("  Penyerang akan memilih jalur termudah, bukan menyerang keduanya.");
        System.out.println();

        for (String[] scheme : SCHEME_LAYERS) {
            String schemeName    = scheme[0];
            String pubLayer      = scheme[1];
            int    essPublic     = Integer.parseInt(scheme[2]);
            String symLayer      = scheme[3];
            int    essSym        = Integer.parseInt(scheme[4]);

            String bottleneck    = (essPublic < essSym) ? pubLayer : symLayer;
            int    essBottleneck = Math.min(essPublic, essSym);

            BigInteger ksBottleneck = BigInteger.TWO.pow(essBottleneck);
            BigDecimal gpuSpd       = (BigDecimal) HARDWARE_PROFILES[1][1];
            BigDecimal tAvgGpu      = calculateTimeYears(ksBottleneck, gpuSpd, true);
            BigDecimal ratio        = tAvgGpu.divide(AGE_OF_UNIVERSE_YEARS, MathContext.DECIMAL64);

            System.out.printf("  +-- Skema: %s%n", schemeName);
            System.out.printf("  |   Lapisan publik   : %-20s -> ESS = %d bit%n", pubLayer, essPublic);
            System.out.printf("  |   Lapisan simetris : %-20s -> ESS = %d bit%n", symLayer, essSym);
            System.out.printf("  |   Bottleneck       : %-20s <- LAPISAN TERLEMAH%n", bottleneck);
            System.out.printf("  |   ESS Bottleneck   : %d bit%n", essBottleneck);
            System.out.printf("  |   T_avg GPU (bottleneck): %s%n", formatTime(tAvgGpu));
            System.out.printf("  +-- ~ %s x umur alam semesta%n", formatScientific(ratio));
            System.out.println();
        }

        System.out.println("  KESIMPULAN:");
        System.out.println("  Pada KEDUA skema, lapisan kunci publik (RSA-2048 / DH-2048) adalah");
        System.out.println("  bottleneck dengan ESS 112-bit, jauh di bawah AES-256 (256-bit).");
        System.out.println("  Meski demikian, ESS 112-bit masih dikategorikan aman untuk");
        System.out.println("  penggunaan jangka menengah menurut NIST SP 800-57 Part 1 Rev. 5.");
        System.out.println("  Untuk keamanan jangka panjang (post-2030), NIST merekomendasikan");
        System.out.println("  RSA/DH dengan modulus >= 3072 bit (ESS = 128 bit).");
        printSeparator('=', 76);
    }

    // ========================================================================
    //  HELPERS: KALKULASI
    // ========================================================================

    /**
     * Menghitung estimasi waktu serangan dalam TAHUN.
     *
     * @param keyspace  Effective keyspace = 2^ESS
     * @param speed     Kecepatan penyerang dalam operasi/detik
     * @param average   true  -> T_avg = keyspace / (2 * speed * seconds_per_year)
     *                  false -> T_worst = keyspace / (speed * seconds_per_year)
     */
    public static BigDecimal calculateTimeYears(BigInteger keyspace, BigDecimal speed, boolean average) {
        BigDecimal ks      = new BigDecimal(keyspace);
        BigDecimal divisor = speed.multiply(SECONDS_PER_YEAR, MathContext.DECIMAL64);
        if (average) {
            divisor = divisor.multiply(BigDecimal.valueOf(2), MathContext.DECIMAL64);
        }
        return ks.divide(divisor, MathContext.DECIMAL64);
    }

    // ========================================================================
    //  HELPERS: FORMAT OUTPUT
    // ========================================================================

    /**
     * Memformat nilai tahun ke satuan yang paling bermakna.
     * Jika < 1 tahun, turun ke hari/jam/menit/detik.
     */
    private static String formatTime(BigDecimal years) {
        if (years.compareTo(BigDecimal.ONE) >= 0) {
            return formatScientific(years) + " tahun";
        }
        // Konversi ke detik untuk nilai sangat kecil
        BigDecimal seconds = years.multiply(SECONDS_PER_YEAR, MathContext.DECIMAL64);
        if (seconds.compareTo(BigDecimal.valueOf(60)) < 0) {
            return String.format(Locale.US, "%.2f detik", seconds.doubleValue());
        }
        if (seconds.compareTo(BigDecimal.valueOf(3600)) < 0) {
            return String.format(Locale.US, "%.2f menit", seconds.doubleValue() / 60);
        }
        if (seconds.compareTo(BigDecimal.valueOf(86400)) < 0) {
            return String.format(Locale.US, "%.2f jam", seconds.doubleValue() / 3600);
        }
        BigDecimal days = seconds.divide(BigDecimal.valueOf(86400), MathContext.DECIMAL64);
        return formatScientific(days) + " hari";
    }

    /**
     * Format BigDecimal ke notasi ilmiah dengan Locale.US (titik sebagai desimal).
     */
    private static String formatScientific(BigDecimal value) {
        if (value.compareTo(BigDecimal.ZERO) == 0) return "0";
        double d = value.doubleValue();
        if (!Double.isInfinite(d) && !Double.isNaN(d) && d > 0) {
            return String.format(Locale.US, "%.3e", d);
        }
        return value.round(new MathContext(4, RoundingMode.HALF_UP)).toString();
    }

    // ========================================================================
    //  HELPERS: DISPLAY
    // ========================================================================
    private static void printHeader() {
        System.out.println();
        printSeparator('=', 76);
        System.out.println("   SIMULASI KEAMANAN LAPISAN KUNCI PUBLIK");
        System.out.println("   RSA-2048 dan Diffie-Hellman 2048-bit");
        System.out.println("   Metode: Equivalent Security Strength (ESS)");
        System.out.println("   Acuan : NIST SP 800-57 Part 1 Rev. 5, Tabel 2");
        printSeparator('=', 76);
    }

    private static void printEssConcept() {
        System.out.println();
        System.out.println("  KONSEP ESS (Equivalent Security Strength):");
        printSeparator('-', 76);
        System.out.println("  Algoritma kunci publik tidak diserang dengan mencoba semua kunci.");
        System.out.println("  Serangannya adalah serangan MATEMATIS yang jauh lebih efisien:");
        System.out.println("    - RSA      -> Integer Factorization (GNFS)");
        System.out.println("    - DH/DSA   -> Discrete Logarithm (Index Calculus)");
        System.out.println();
        System.out.println("  ESS menyatakan: 'membobol algoritma ini setara kesulitannya dengan");
        System.out.println("  brute force kunci simetris ESS-bit.'");
        System.out.println();
        System.out.printf("  %-26s  %-14s  %-8s%n", "Algoritma", "Param (bit)", "ESS (bit)");
        printSeparator('-', 55);
        System.out.printf("  %-26s  %-14s  %-8s%n", "RSA-2048",              "2048",  "112");
        System.out.printf("  %-26s  %-14s  %-8s%n", "Diffie-Hellman 2048",   "2048",  "112");
        System.out.printf("  %-26s  %-14s  %-8s  <- digunakan di proyek%n", "AES-256", "256", "256");
        System.out.println();
        System.out.println("  RSA-2048 != aman seperti AES-2048.");
        System.out.println("  Panjang parameter != bit keamanan pada kriptografi asimetris.");
        System.out.println();
    }

    private static void printFooter() {
        System.out.println();
        System.out.println("  REFERENSI:");
        System.out.println("  [1] NIST SP 800-57 Part 1 Rev. 5 (2020) - Recommendation for Key");
        System.out.println("      Management, Tabel 2: Comparable security strengths.");
        System.out.println("  [2] NIST SP 800-131A Rev. 2 (2019) - Transitioning the Use of");
        System.out.println("      Cryptographic Algorithms and Key Lengths.");
        System.out.println("  [3] Schneier, Applied Cryptography, 2nd ed.");
        System.out.println();
        printSeparator('=', 76);
    }

    private static void printSeparator(char ch, int length) {
        System.out.println("  " + String.valueOf(ch).repeat(length));
    }
}
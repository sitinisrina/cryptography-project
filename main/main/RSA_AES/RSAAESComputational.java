package main.RSA_AES;

import main.BenchmarkHelper;

public class RSAAESComputational {

    public static void main(String[] args) {
        try {
            BenchmarkHelper.BenchmarkResult aliceResult =
                    BenchmarkHelper.readBenchmarkResult("alice_RSA_benchmark.txt");

            BenchmarkHelper.BenchmarkResult bobResult =
                    BenchmarkHelper.readBenchmarkResult("bob_RSA_benchmark.txt");

            long totalExecutionTimeNs =
                    aliceResult.getExecutionTimeNs() + bobResult.getExecutionTimeNs();

            long totalMemoryUsageBytes =
                    aliceResult.getMemoryUsageBytes() + bobResult.getMemoryUsageBytes();

            System.out.println("Hasil Perhitungan Komputasional RSA-AES");
            System.out.println("Waktu eksekusi Alice : " + aliceResult.getExecutionTimeNs() + " ns");
            System.out.println("Waktu eksekusi Bob   : " + bobResult.getExecutionTimeNs() + " ns");
            System.out.println("Total end-to-end     : " + totalExecutionTimeNs + " ns");
            System.out.println();
            System.out.println("Memori Alice         : " + aliceResult.getMemoryUsageBytes() + " bytes");
            System.out.println("Memori Bob           : " + bobResult.getMemoryUsageBytes() + " bytes");
            System.out.println("Total end-to-end     : " + totalMemoryUsageBytes + " bytes");

        } catch (Exception e) {
            System.err.println("Gagal membaca hasil benchmark RSA-AES.");
            e.printStackTrace();
        }
    }
}
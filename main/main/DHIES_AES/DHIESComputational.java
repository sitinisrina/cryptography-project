package main.DHIES_AES;

import main.BenchmarkHelper;

public class DHIESComputational {

    public static void main(String[] args) {
        try {
            BenchmarkHelper.BenchmarkResult aliceResult =
                    BenchmarkHelper.readBenchmarkResult("alice_benchmark.txt");

            BenchmarkHelper.BenchmarkResult bobResult =
                    BenchmarkHelper.readBenchmarkResult("bob_benchmark.txt");

            long totalExecutionTimeNs = aliceResult.getExecutionTimeNs() + bobResult.getExecutionTimeNs();
            long totalMemoryUsageBytes = aliceResult.getMemoryUsageBytes() + bobResult.getMemoryUsageBytes();

            System.out.println("Hasil Perhitungan Komputasional DHIES-AES");
            System.out.println("Waktu eksekusi Alice : " + aliceResult.getExecutionTimeNs() + " ns");
            System.out.println("Waktu eksekusi Bob   : " + bobResult.getExecutionTimeNs() + " ns");
            System.out.println("Total end-to-end     : " + totalExecutionTimeNs + " ns");
            System.out.println();
            System.out.println("Memori Alice         : " + aliceResult.getMemoryUsageBytes() + " bytes");
            System.out.println("Memori Bob           : " + bobResult.getMemoryUsageBytes() + " bytes");
            System.out.println("Total end-to-end     : " + totalMemoryUsageBytes + " bytes");

        } catch (Exception e) {
            System.err.println("Gagal membaca hasil benchmark Alice/Bob.");
            e.printStackTrace();
        }
    }
}

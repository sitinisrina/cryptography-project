package main;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public class BenchmarkHelper {

    public static class BenchmarkResult {
        private final long executionTimeNs;
        private final long memoryUsageBytes;

        public BenchmarkResult(long executionTimeNs, long memoryUsageBytes) {
            this.executionTimeNs = executionTimeNs;
            this.memoryUsageBytes = memoryUsageBytes;
        }

        public long getExecutionTimeNs() {
            return executionTimeNs;
        }

        public long getMemoryUsageBytes() {
            return memoryUsageBytes;
        }
    }

    @FunctionalInterface
    public interface BenchmarkTask {
        void run() throws Exception;
    }

    public static BenchmarkResult measure(BenchmarkTask task) throws Exception {
        forceGarbageCollection();

        long memoryBefore = getUsedMemory();
        long startTime = System.nanoTime();

        task.run();

        long endTime = System.nanoTime();
        long memoryAfter = getUsedMemory();

        long memoryUsageBytes = Math.max(0L, memoryAfter - memoryBefore);
        return new BenchmarkResult(endTime - startTime, memoryUsageBytes);
    }

    public static long getUsedMemory() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private static void forceGarbageCollection() throws InterruptedException {
        System.gc();
        Thread.sleep(100);
    }

    public static void writeBenchmarkResult(String filePath,
                                            String role,
                                            BenchmarkResult result) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(Path.of(filePath))) {
            writer.write("role=" + role);
            writer.newLine();
            writer.write("executionTimeNs=" + result.getExecutionTimeNs());
            writer.newLine();
            writer.write("memoryUsageBytes=" + result.getMemoryUsageBytes());
            writer.newLine();
        }
    }

    public static BenchmarkResult readBenchmarkResult(String filePath) throws IOException {
        Map<String, String> values = new LinkedHashMap<>();

        try (BufferedReader reader = Files.newBufferedReader(Path.of(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || !trimmed.contains("=")) {
                    continue;
                }

                String[] parts = trimmed.split("=", 2);
                values.put(parts[0].trim(), parts[1].trim());
            }
        }

        long executionTimeNs = Long.parseLong(values.getOrDefault("executionTimeNs", "0"));
        long memoryUsageBytes = Long.parseLong(values.getOrDefault("memoryUsageBytes", "0"));

        return new BenchmarkResult(executionTimeNs, memoryUsageBytes);
    }
}

package main.GUI;

import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.scene.web.WebEngine;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import main.Helper;
import main.RSA_AES.PovAliceasSender;
import main.RSA_AES.PovBobasReceiver;
import main.DHIES_AES.DHIESAliceasSender;
import main.DHIES_AES.DHIESBobasReceiver;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.imageio.ImageIO;
import javafx.embed.swing.SwingFXUtils;
import javafx.scene.media.Media;
import javafx.scene.media.MediaPlayer;
import javafx.scene.image.WritableImage;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;

/**
 * AppBridge — jembatan antara JavaScript (HTML) dan Java.
 *
 * Semua method public di class ini dapat dipanggil dari JavaScript:
 *   window.javaBridge.namaMethod(parameter);
 *
 * Aturan thread:
 * - Method dipanggil dari JS di JavaFX Application Thread
 * - Operasi berat (enkripsi, hashing) dijalankan di background Task
 * - Hasil dikirim kembali ke JS via runJS() di Platform.runLater()
 */
public class AppBridge {

    private final WebEngine engine;
    private final Stage stage;

    // State sesi — disimpan antar layar
    private File selectedFile;
    private String operationMode;   // "ENCRYPT" atau "DECRYPT"
    private String selectedScheme;  // "RSA_AES" atau "DHIES_AES"
    private String plaintextHash;   // SHA-256 hash dari plaintext asli
    private File outputFile;        // File hasil enkripsi/dekripsi

    // Working directory — root project (tempat file kunci berada)
    private final String workingDir = System.getProperty("user.dir");

    public AppBridge(WebEngine engine, Stage stage) {
        this.engine = engine;
        this.stage = stage;
    }

    // =========================================================
    // NAVIGASI
    // =========================================================

    public void navigateTo(String htmlFile) {
        Platform.runLater(() -> {
            String url = getClass().getResource("/main/GUI/resources/html/" + htmlFile).toExternalForm();
            engine.load(url);
        });
    }

    // =========================================================
    // LAYAR 1 — MODE & FILE PICKER
    // =========================================================

    public void setMode(String mode) {
        this.operationMode = mode;
    }

    /**
     * Membuka file chooser dialog.
     * Callback JS: onFileSelected(filePath, fileName, fileSizeBytes, fileExtension)
     *              onFileError(message)
     */
    public void selectFile() {
        Platform.runLater(() -> {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Pilih File");

            if ("DECRYPT".equals(operationMode)) {
                chooser.getExtensionFilters().add(
                    new FileChooser.ExtensionFilter("File Terenkripsi (*.bin)", "*.bin")
                );
            } else {
                chooser.getExtensionFilters().addAll(
                    new FileChooser.ExtensionFilter("Semua File", "*.*"),
                    new FileChooser.ExtensionFilter("Video (*.mp4)", "*.mp4"),
                    new FileChooser.ExtensionFilter("PDF (*.pdf)", "*.pdf"),
                    new FileChooser.ExtensionFilter("Teks (*.txt)", "*.txt"),
                    new FileChooser.ExtensionFilter("Gambar", "*.png", "*.jpg", "*.jpeg")
                );
            }

            chooser.setInitialDirectory(new File(workingDir));

            File file = chooser.showOpenDialog(stage);
            if (file != null) {
                long maxSize = 1L * 1024 * 1024 * 1024; // 1 GB
                if (file.length() > maxSize) {
                    runJS("onFileError('Ukuran file melebihi batas 1 GB.')");
                    return;
                }
                selectedFile = file;
                String ext = getExtension(file.getName());
                runJS(String.format(
                    "onFileSelected('%s', '%s', %d, '%s')",
                    escapeJS(file.getAbsolutePath()),
                    escapeJS(file.getName()),
                    file.length(),
                    ext
                ));
            }
        });
    }

    // =========================================================
    // LAYAR 2 — PREVIEW FILE
    // =========================================================

    /**
     * Mengirim metadata file ke JS saat Layar 2 load.
     * Callback JS: onFileMetadata(filePath, fileName, fileSizeBytes, fileExtension)
     */
    public void getFileMetadata() {
        if (selectedFile == null) {
            runJS("onFileError('Tidak ada file yang dipilih.')");
            return;
        }
        String ext = getExtension(selectedFile.getName());
        runJS(String.format(
            "onFileMetadata('%s', '%s', %d, '%s')",
            escapeJS(selectedFile.getAbsolutePath()),
            escapeJS(selectedFile.getName()),
            selectedFile.length(),
            ext
        ));
    }

    /**
     * Render halaman pertama PDF sebagai base64 PNG via PDFBox.
     * Callback JS: onPdfPreview(base64PngString)
     *              onPreviewError(message)
     */
    public void getPdfPreview() {
        if (selectedFile == null) { runJS("onPreviewError('Tidak ada file.')"); return; }

        Task<String> task = new Task<>() {
            @Override
            protected String call() throws Exception {
                try (PDDocument doc = Loader.loadPDF(selectedFile)) {
                    PDFRenderer renderer = new PDFRenderer(doc);
                    BufferedImage img = renderer.renderImageWithDPI(0, 120);
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ImageIO.write(img, "png", baos);
                    return Base64.getEncoder().encodeToString(baos.toByteArray());
                }
            }
        };
        task.setOnSucceeded(e -> runJS("onPdfPreview('data:image/png;base64," + task.getValue() + "')"));
        task.setOnFailed(e -> {
            String msg = task.getException() != null ? task.getException().getMessage() : "Gagal render PDF";
            runJS("onPreviewError('" + escapeJS(msg) + "')");
        });
        new Thread(task).start();
    }

    /**
     * Mendapatkan jumlah halaman PDF.
     * Callback JS: onPdfPageCount(count)
     */
    public void getPdfPageCount() {
        if (selectedFile == null) return;
        Task<Integer> task = new Task<>() {
            @Override
            protected Integer call() throws Exception {
                try (PDDocument doc = Loader.loadPDF(selectedFile)) {
                    return doc.getNumberOfPages();
                }
            }
        };
        task.setOnSucceeded(e -> runJS("onPdfPageCount(" + task.getValue() + ")"));
        task.setOnFailed(e -> runJS("onPdfPageCount(0)"));
        new Thread(task).start();
    }

    /**
     * Snapshot frame pertama video MP4 sebagai base64 PNG.
     * Callback JS: onVideoThumbnail(base64PngString, durationSeconds)
     *              onPreviewError(message)
     */
    public void getVideoThumbnail() {
        if (selectedFile == null) { runJS("onPreviewError('Tidak ada file.')"); return; }

        Platform.runLater(() -> {
            try {
                Media media = new Media(selectedFile.toURI().toString());
                MediaPlayer player = new MediaPlayer(media);

                player.setOnReady(() -> {
                    // Ambil durasi video
                    double durationSec = media.getDuration().toSeconds();

                    // Snapshot frame pertama
                    player.seek(javafx.util.Duration.ZERO);
                    WritableImage snapshot = player.getMedia() != null
                        ? new WritableImage(480, 270) : null;

                    // Gunakan SnapshotParameters via MediaView
                    javafx.scene.media.MediaView mv = new javafx.scene.media.MediaView(player);
                    mv.setFitWidth(480);
                    mv.setFitHeight(270);
                    mv.setPreserveRatio(true);

                    // Render scene offscreen
                    javafx.scene.Scene offscreen = new javafx.scene.Scene(
                        new javafx.scene.layout.StackPane(mv), 480, 270);

                    // Delay singkat agar frame sempat di-render
                    javafx.animation.PauseTransition pause = new javafx.animation.PauseTransition(
                        javafx.util.Duration.millis(300));
                    pause.setOnFinished(evt -> {
                        try {
                            WritableImage img = mv.snapshot(new javafx.scene.SnapshotParameters(), null);
                            BufferedImage bi = SwingFXUtils.fromFXImage(img, null);
                            ByteArrayOutputStream baos = new ByteArrayOutputStream();
                            ImageIO.write(bi, "png", baos);
                            String b64 = Base64.getEncoder().encodeToString(baos.toByteArray());
                            player.dispose();
                            runJS(String.format("onVideoThumbnail('data:image/png;base64,%s', %.1f)", b64, durationSec));
                        } catch (Exception ex) {
                            player.dispose();
                            runJS("onPreviewError('" + escapeJS(ex.getMessage()) + "')");
                        }
                    });
                    pause.play();
                });

                player.setOnError(() -> {
                    player.dispose();
                    runJS("onPreviewError('Tidak dapat membaca file video.')");
                });

            } catch (Exception ex) {
                runJS("onPreviewError('" + escapeJS(ex.getMessage()) + "')");
            }
        });
    }

    /**
     * Membaca file gambar (PNG/JPG) sebagai base64.
     * Callback JS: onImagePreview(base64DataUrl)
     */
    public void getImagePreview() {
        if (selectedFile == null) { runJS("onPreviewError('Tidak ada file.')"); return; }

        Task<String> task = new Task<>() {
            @Override
            protected String call() throws Exception {
                String ext = getExtension(selectedFile.getName());
                String mime = ext.equals("png") ? "image/png" : "image/jpeg";
                byte[] bytes = Files.readAllBytes(selectedFile.toPath());
                return "data:" + mime + ";base64," + Base64.getEncoder().encodeToString(bytes);
            }
        };
        task.setOnSucceeded(e -> runJS("onImagePreview('" + task.getValue() + "')"));
        task.setOnFailed(e -> runJS("onPreviewError('Gagal membaca gambar.')"));
        new Thread(task).start();
    }

    /**
     * Membaca 500 karakter pertama file teks.
     * Callback JS: onTextPreview(text)
     */
    public void getTextPreview() {
        if (selectedFile == null) { runJS("onPreviewError('Tidak ada file.')"); return; }

        Task<String> task = new Task<>() {
            @Override
            protected String call() throws Exception {
                byte[] bytes = new byte[2048];
                int read;
                try (FileInputStream fis = new FileInputStream(selectedFile)) {
                    read = fis.read(bytes);
                }
                String raw = new String(bytes, 0, read, java.nio.charset.StandardCharsets.UTF_8);
                return raw.length() > 500 ? raw.substring(0, 500) + "..." : raw;
            }
        };
        task.setOnSucceeded(e -> runJS("onTextPreview('" + escapeJS(task.getValue()) + "')"));
        task.setOnFailed(e -> runJS("onPreviewError('Gagal membaca file teks.')"));
        new Thread(task).start();
    }

    /**
     * Menghitung SHA-256 secara streaming dengan progress.
     * Callback JS: onHashProgress(percent)
     *              onHashComplete(hashHex)
     *              onHashError(message)
     */
    public void computeHash() {
        if (selectedFile == null) {
            runJS("onHashError('Tidak ada file yang dipilih.')");
            return;
        }

        Task<String> task = new Task<>() {
            @Override
            protected String call() throws Exception {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                long total = selectedFile.length();
                long processed = 0;
                byte[] buffer = new byte[8 * 1024 * 1024]; // 8 MB per chunk

                try (FileInputStream fis = new FileInputStream(selectedFile)) {
                    int n;
                    int lastPercent = -1;
                    while ((n = fis.read(buffer)) != -1) {
                        md.update(buffer, 0, n);
                        processed += n;
                        int percent = (int) ((processed * 100) / total);
                        if (percent != lastPercent) {
                            lastPercent = percent;
                            final int p = percent;
                            runJS("onHashProgress(" + p + ")");
                        }
                    }
                }

                byte[] hashBytes = md.digest();
                StringBuilder sb = new StringBuilder();
                for (byte b : hashBytes) sb.append(String.format("%02x", b));
                return sb.toString();
            }
        };

        task.setOnSucceeded(e -> {
            plaintextHash = task.getValue();
            runJS("onHashComplete('" + plaintextHash + "')");
        });

        task.setOnFailed(e -> {
            String msg = task.getException() != null
                ? task.getException().getMessage() : "Unknown error";
            runJS("onHashError('" + escapeJS(msg) + "')");
        });

        new Thread(task).start();
    }

    // =========================================================
    // LAYAR 3 — SKEMA & KUNCI
    // =========================================================

    public void setScheme(String scheme) {
        this.selectedScheme = scheme;
    }

    /**
     * Auto-detect dan load file kunci dari working directory.
     * Callback JS: onKeyLoaded(keyFileName, fingerprint)
     *              onKeyError(message)
     */
    public void loadKey() {
        String keyFileName = getKeyFileName();
        File keyFile = new File(workingDir, keyFileName);

        if (!keyFile.exists()) {
            runJS("onKeyError('File kunci tidak ditemukan: " + keyFileName + "')");
            return;
        }

        try {
            byte[] keyBytes = Helper.fromFiletoBinary(keyFile.getAbsolutePath());

            // Fingerprint: SHA-256 dari key bytes, tampilkan 16 byte pertama
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] fp = md.digest(keyBytes);
            StringBuilder sbFp = new StringBuilder();
            for (int i = 0; i < Math.min(16, fp.length); i++) {
                if (i > 0 && i % 2 == 0) sbFp.append(":");
                sbFp.append(String.format("%02x", fp[i]));
            }

            // Konversi key bytes ke Base64 dengan line wrap 64 karakter
            String b64Full = Base64.getEncoder().encodeToString(keyBytes);
            StringBuilder sbKey = new StringBuilder();
            for (int i = 0; i < b64Full.length(); i += 64) {
                sbKey.append(b64Full, i, Math.min(i + 64, b64Full.length()));
                sbKey.append("\n");
            }

            // Tentukan label header/footer
            boolean isRsa = "RSA_AES".equals(selectedScheme);
            boolean isPrivate = "DECRYPT".equals(operationMode);
            String keyLabel = isRsa
                ? (isPrivate ? "RSA PRIVATE KEY" : "RSA PUBLIC KEY")
                : (isPrivate ? "DH PRIVATE KEY"  : "DH PUBLIC KEY");

            runJS(String.format("onKeyLoaded('%s', '%s', '%s', '%s')",
                escapeJS(keyFileName),
                escapeJS(sbFp.toString()),
                escapeJS(sbKey.toString()),
                escapeJS(keyLabel)
            ));

        } catch (Exception ex) {
            runJS("onKeyError('" + escapeJS(ex.getMessage()) + "')");
        }
    }

    // =========================================================
    // LAYAR 4 — PROSES ENKRIPSI / DEKRIPSI
    // =========================================================

    /**
     * Memulai proses sesuai mode dan skema yang dipilih.
     * Callback JS bertahap:
     *   onStepStart(stepIndex, stepName)
     *   onStepDone(stepIndex, durationMs, info)
     *   onProcessComplete(outputPath, durationMs, outputSizeBytes)
     *   onProcessError(message)
     */
    public void startProcess() {
        if (selectedFile == null || operationMode == null || selectedScheme == null) {
            runJS("onProcessError('State tidak lengkap. Kembali ke layar 1.')");
            return;
        }

        Task<Void> task = new Task<>() {
            @Override
            protected Void call() throws Exception {
                if ("ENCRYPT".equals(operationMode)) {
                    runEncrypt();
                } else {
                    runDecrypt();
                }
                return null;
            }
        };

        task.setOnFailed(e -> {
            String msg = task.getException() != null
                ? task.getException().getMessage() : "Unknown error";
            runJS("onProcessError('" + escapeJS(msg) + "')");
        });

        new Thread(task).start();
    }

    private void runEncrypt() throws Exception {
        long startTotal = System.currentTimeMillis();

        if ("RSA_AES".equals(selectedScheme)) {

            notifyStepStart(1, "Membaca file plaintext");
            long t1 = System.currentTimeMillis();
            byte[] fileContent = Helper.fromFiletoBinary(selectedFile.getAbsolutePath());
            notifyStepDone(1, System.currentTimeMillis() - t1, formatSize(fileContent.length) + " dibaca");

            notifyStepStart(2, "Membangkitkan session key AES-256");
            long t2 = System.currentTimeMillis();
            var sessionKey = main.RSA_AES.HybridRSA_AES.generateSessionKey();
            notifyStepDone(2, System.currentTimeMillis() - t2, "256-bit key dibangkitkan");

            notifyStepStart(3, "Enkripsi data → AES-256-GCM");
            long t3 = System.currentTimeMillis();
            byte[] encContent = main.RSA_AES.HybridRSA_AES.encryptMessage(fileContent, sessionKey);
            notifyStepDone(3, System.currentTimeMillis() - t3, formatSize(encContent.length) + " ciphertext");

            notifyStepStart(4, "Enkripsi session key → RSA-OAEP-SHA256");
            long t4 = System.currentTimeMillis();
            PublicKey bobPubKey = Helper.loadPublicKey(
                new File(workingDir, "bob_rsa_public_key.bin").getAbsolutePath(), "RSA");
            byte[] encKey = main.RSA_AES.HybridRSA_AES.encryptSessionKey(sessionKey, bobPubKey);
            notifyStepDone(4, System.currentTimeMillis() - t4, encKey.length + " byte encrypted key");

            notifyStepStart(5, "Membangun paket output & menyimpan file");
            long t5 = System.currentTimeMillis();
            byte[] pkg = PovAliceasSender.buildEncryptedPackage(encKey, encContent);
            String outPath = new File(workingDir, "encrypted_rsa_aes_package.bin").getAbsolutePath();
            Helper.writeBinarytoFile(pkg, outPath);
            outputFile = new File(outPath);
            notifyStepDone(5, System.currentTimeMillis() - t5, formatSize(pkg.length) + " disimpan");

        } else { // DHIES_AES

            notifyStepStart(1, "Membaca file plaintext");
            long t1 = System.currentTimeMillis();
            byte[] fileContent = Helper.fromFiletoBinary(selectedFile.getAbsolutePath());
            notifyStepDone(1, System.currentTimeMillis() - t1, formatSize(fileContent.length) + " dibaca");

            notifyStepStart(2, "Memuat kunci publik DH Bob");
            long t2 = System.currentTimeMillis();
            PublicKey bobPubKey = Helper.loadPublicKey(
                new File(workingDir, "bob_DH_public_key.bin").getAbsolutePath(), "DH");
            notifyStepDone(2, System.currentTimeMillis() - t2, "Kunci DH Bob dimuat");

            notifyStepStart(3, "Membangkitkan kunci ephemeral Alice (u, U=g^u)");
            long t3 = System.currentTimeMillis();
            var aliceKP = main.DHIES_AES.DHIES.generateKeyPairFromPeerPublicKey(bobPubKey);
            notifyStepDone(3, System.currentTimeMillis() - t3, "Kunci ephemeral siap");

            notifyStepStart(4, "Menghitung shared secret Z = DH(u, BobPublicKey)");
            long t4 = System.currentTimeMillis();
            byte[] sharedSecret = main.DHIES_AES.DHIES.computeSharedSecret(
                aliceKP.getPrivate(), bobPubKey);
            notifyStepDone(4, System.currentTimeMillis() - t4, sharedSecret.length + " byte");

            notifyStepStart(5, "Derive encKey & macKey via HKDF-SHA256, enkripsi AES-256-CTR");
            long t5 = System.currentTimeMillis();
            main.DHIES_AES.HybridDHIES_AES.HybridEncryptData result =
                main.DHIES_AES.HybridDHIES_AES.encrypt(fileContent, sharedSecret);
            notifyStepDone(5, System.currentTimeMillis() - t5,
                formatSize(result.getCiphertext().length) + " ciphertext");

            notifyStepStart(6, "Generate tag T = HMAC-SHA256(macKey, salt ‖ C)");
            long t6 = System.currentTimeMillis();
            notifyStepDone(6, System.currentTimeMillis() - t6,
                result.getTag().length + " byte tag");

            notifyStepStart(7, "Membangun paket output (U ‖ salt ‖ C ‖ T)");
            long t7 = System.currentTimeMillis();
            byte[] pkg = Helper.buildEncryptedPackage(
                aliceKP.getPublic().getEncoded(),
                result.getSalt(), result.getCiphertext(), result.getTag());
            String outPath = new File(workingDir, "encrypted_DHIES_file.bin").getAbsolutePath();
            Helper.writeBinarytoFile(pkg, outPath);
            outputFile = new File(outPath);
            notifyStepDone(7, System.currentTimeMillis() - t7, formatSize(pkg.length) + " disimpan");
        }

        long totalMs = System.currentTimeMillis() - startTotal;
        runJS(String.format("onProcessComplete('%s', %d, %d)",
            escapeJS(outputFile.getAbsolutePath()), totalMs, outputFile.length()));
    }

    private void runDecrypt() throws Exception {
        long startTotal = System.currentTimeMillis();

        if ("RSA_AES".equals(selectedScheme)) {

            notifyStepStart(1, "Membaca paket ciphertext");
            long t1 = System.currentTimeMillis();
            byte[] encPkg = Helper.fromFiletoBinary(selectedFile.getAbsolutePath());
            notifyStepDone(1, System.currentTimeMillis() - t1, formatSize(encPkg.length) + " dibaca");

            notifyStepStart(2, "Parsing paket — ekstrak Ck dan Cm");
            long t2 = System.currentTimeMillis();
            byte[][] parsed = PovBobasReceiver.parseEncryptedPackage(encPkg);
            notifyStepDone(2, System.currentTimeMillis() - t2,
                "Ck: " + parsed[0].length + " byte, Cm: " + formatSize(parsed[1].length));

            notifyStepStart(3, "Dekripsi session key → RSA-OAEP-SHA256");
            long t3 = System.currentTimeMillis();
            PrivateKey bobPrivKey = Helper.loadPrivateKey(
                new File(workingDir, "bob_rsa_private_key.bin").getAbsolutePath(), "RSA");
            var sessionKey = main.RSA_AES.HybridRSA_AES.decryptSessionKey(parsed[0], bobPrivKey);
            notifyStepDone(3, System.currentTimeMillis() - t3, "Session key dipulihkan");

            notifyStepStart(4, "Dekripsi data → AES-256-GCM + verifikasi auth tag");
            long t4 = System.currentTimeMillis();
            byte[] plaintext = main.RSA_AES.HybridRSA_AES.decryptMessage(parsed[1], sessionKey);
            notifyStepDone(4, System.currentTimeMillis() - t4, formatSize(plaintext.length) + " plaintext");

            notifyStepStart(5, "Menyimpan hasil dekripsi");
            long t5 = System.currentTimeMillis();
            String outPath = new File(workingDir, "decrypted_message.mp4").getAbsolutePath();
            Helper.writeBinarytoFile(plaintext, outPath);
            outputFile = new File(outPath);
            notifyStepDone(5, System.currentTimeMillis() - t5, "File disimpan");

        } else { // DHIES_AES

            notifyStepStart(1, "Membaca paket ciphertext DHIES");
            long t1 = System.currentTimeMillis();
            byte[] encPkg = Helper.fromFiletoBinary(selectedFile.getAbsolutePath());
            notifyStepDone(1, System.currentTimeMillis() - t1, formatSize(encPkg.length) + " dibaca");

            notifyStepStart(2, "Parsing paket — ekstrak U, salt, C, T");
            long t2 = System.currentTimeMillis();
            byte[][] parsed = Helper.parseDHIESPackage(encPkg);
            notifyStepDone(2, System.currentTimeMillis() - t2,
                "C: " + formatSize(parsed[2].length));

            notifyStepStart(3, "Menghitung shared secret Z = DH(BobPrivKey, U)");
            long t3 = System.currentTimeMillis();
            PrivateKey bobPrivKey = Helper.loadPrivateKey(
                new File(workingDir, "bob_DH_private_key.bin").getAbsolutePath(), "DH");
            PublicKey aliceEphPub = Helper.loadPublicKeyFromBytes(parsed[0], "DH");
            byte[] sharedSecret = main.DHIES_AES.DHIES.computeSharedSecret(bobPrivKey, aliceEphPub);
            notifyStepDone(3, System.currentTimeMillis() - t3, sharedSecret.length + " byte");

            notifyStepStart(4, "Verifikasi HMAC-SHA256 & dekripsi AES-256-CTR");
            long t4 = System.currentTimeMillis();
            main.DHIES_AES.HybridDHIES_AES.HybridEncryptData hybridData =
                new main.DHIES_AES.HybridDHIES_AES.HybridEncryptData(parsed[1], parsed[2], parsed[3]);
            byte[] plaintext = main.DHIES_AES.HybridDHIES_AES.decrypt(hybridData, sharedSecret);
            notifyStepDone(4, System.currentTimeMillis() - t4, formatSize(plaintext.length) + " plaintext");

            notifyStepStart(5, "Menyimpan hasil dekripsi");
            long t5 = System.currentTimeMillis();
            String outPath = new File(workingDir, "decrypted_DHIES_message.mp4").getAbsolutePath();
            Helper.writeBinarytoFile(plaintext, outPath);
            outputFile = new File(outPath);
            notifyStepDone(5, System.currentTimeMillis() - t5, "File disimpan");
        }

        long totalMs = System.currentTimeMillis() - startTotal;
        runJS(String.format("onProcessComplete('%s', %d, %d)",
            escapeJS(outputFile.getAbsolutePath()), totalMs, outputFile.length()));
    }

    // =========================================================
    // LAYAR 5 — HASIL & VERIFIKASI
    // =========================================================

    /**
     * Mengirim data hasil ke Layar 5 saat pertama load.
     * Callback JS: onResultData(mode, scheme, hexDump, outputSizeBytes, outputFileName)
     */
    public void getResultData() {
        if (outputFile == null) {
            runJS("onResultError('Tidak ada hasil proses.')");
            return;
        }
        try {
            byte[] previewBytes = new byte[64];
            int read;
            try (FileInputStream fis = new FileInputStream(outputFile)) {
                read = fis.read(previewBytes);
            }
            StringBuilder hexSb = new StringBuilder();
            for (int i = 0; i < read; i++) {
                if (i > 0 && i % 16 == 0) hexSb.append("\\n");
                else if (i > 0 && i % 8 == 0) hexSb.append("  ");
                hexSb.append(String.format("%02x ", previewBytes[i]));
            }
            runJS(String.format("onResultData('%s', '%s', '%s', %d, '%s')",
                escapeJS(operationMode),
                escapeJS(selectedScheme),
                escapeJS(hexSb.toString()),
                outputFile.length(),
                escapeJS(outputFile.getName())
            ));
        } catch (Exception ex) {
            runJS("onResultError('" + escapeJS(ex.getMessage()) + "')");
        }
    }

    /**
     * Verifikasi hash: hitung SHA-256 file output, bandingkan dengan plaintext hash.
     * Callback JS: onHashVerified(decryptedHash, originalHash, isMatch)
     */
    public void verifyHash() {
        if (outputFile == null) {
            runJS("onHashError('Tidak ada file output.')");
            return;
        }
        Task<String> task = new Task<>() {
            @Override
            protected String call() throws Exception {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] buffer = new byte[8 * 1024 * 1024];
                try (FileInputStream fis = new FileInputStream(outputFile)) {
                    int n;
                    while ((n = fis.read(buffer)) != -1) md.update(buffer, 0, n);
                }
                byte[] hashBytes = md.digest();
                StringBuilder sb = new StringBuilder();
                for (byte b : hashBytes) sb.append(String.format("%02x", b));
                return sb.toString();
            }
        };
        task.setOnSucceeded(e -> {
            String decHash = task.getValue();
            boolean match = decHash.equalsIgnoreCase(plaintextHash);
            runJS(String.format("onHashVerified('%s', '%s', %b)",
                decHash, plaintextHash != null ? plaintextHash : "", match));
        });
        task.setOnFailed(e -> {
            String msg = task.getException() != null ? task.getException().getMessage() : "Unknown";
            runJS("onHashError('" + escapeJS(msg) + "')");
        });
        new Thread(task).start();
    }

    public String getPlaintextHash() { return plaintextHash != null ? plaintextHash : ""; }
    public String getMode()          { return operationMode != null ? operationMode : ""; }
    public String getScheme()        { return selectedScheme != null ? selectedScheme : ""; }

    public void resetSession() {
        selectedFile = null;
        operationMode = null;
        selectedScheme = null;
        plaintextHash = null;
        outputFile = null;
    }

    // =========================================================
    // HELPER INTERNAL
    // =========================================================

    protected void runJS(String script) {
        Platform.runLater(() -> {
            try { engine.executeScript(script); }
            catch (Exception e) { System.err.println("[AppBridge] JS error: " + e.getMessage()); }
        });
    }

    private void notifyStepStart(int index, String name) {
        runJS(String.format("onStepStart(%d, '%s')", index, escapeJS(name)));
    }

    private void notifyStepDone(int index, long durationMs, String info) {
        runJS(String.format("onStepDone(%d, %d, '%s')", index, durationMs, escapeJS(info)));
    }

    private String getKeyFileName() {
        if ("RSA_AES".equals(selectedScheme))
            return "ENCRYPT".equals(operationMode) ? "bob_rsa_public_key.bin" : "bob_rsa_private_key.bin";
        else
            return "ENCRYPT".equals(operationMode) ? "bob_DH_public_key.bin" : "bob_DH_private_key.bin";
    }

    private String getExtension(String fileName) {
        int dot = fileName.lastIndexOf('.');
        return dot >= 0 ? fileName.substring(dot + 1).toLowerCase() : "";
    }

    private String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private String escapeJS(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "");
    }
}
package main.GUI;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.web.WebView;
import javafx.scene.web.WebEngine;
import main.GUI.controller.MainController;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import javafx.concurrent.Worker;
import netscape.javascript.JSObject;

public class MainApp extends Application {

    // Controller utama yang mengelola komunikasi Java <-> JS
    private MainController controller;

    @Override
    public void start(Stage primaryStage) {
        // Inisialisasi WebView dan WebEngine
        WebView webView = new WebView();
        WebEngine engine = webView.getEngine();

        // Nonaktifkan klik kanan (tidak relevan untuk aplikasi demo)
        webView.setContextMenuEnabled(false);

        // Inisialisasi controller dengan referensi ke engine
        controller = new MainController(engine, primaryStage);

        // Inject AppBridge ke JavaScript setelah setiap halaman selesai load
        // Ini dipanggil ulang setiap navigasi layar karena JS context reset
        engine.getLoadWorker().stateProperty().addListener((obs, oldState, newState) -> {
            if (newState == Worker.State.SUCCEEDED) {
                JSObject window = (JSObject) engine.executeScript("window");
                window.setMember("javaBridge", controller.getBridge());
            }
        });

        // Load layar pertama (Dashboard)
        engine.load(getClass().getResource("/main/GUI/resources/html/dashboard.html").toExternalForm());

        // Setup scene dan window
        StackPane root = new StackPane(webView);
        Scene scene = new Scene(root, 800, 600);

        primaryStage.setTitle("CryptoDemo — Demonstrasi Skema Kriptografi Hibrida");
        primaryStage.setScene(scene);
        primaryStage.setResizable(false);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
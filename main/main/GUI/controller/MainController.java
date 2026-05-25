package main.GUI.controller;

import javafx.scene.web.WebEngine;
import javafx.stage.Stage;
import main.GUI.AppBridge;

public class MainController {

    private final WebEngine engine;
    private final Stage stage;
    private final AppBridge bridge;

    public MainController(WebEngine engine, Stage stage) {
        this.engine = engine;
        this.stage = stage;
        this.bridge = new AppBridge(engine, stage);
    }

    public AppBridge getBridge() {
        return bridge;
    }

    // Navigasi ke layar tertentu — dipanggil dari AppBridge
    public void navigateTo(String htmlFile) {
        String url = getClass().getResource("/main/GUI/resources/html/" + htmlFile).toExternalForm();
        engine.load(url);
    }
}
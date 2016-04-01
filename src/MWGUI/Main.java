package MWGUI;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

import static Client.Client.closeSmartCardConnection;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception{
        FXMLLoader loader = new FXMLLoader(getClass().getResource("MWgui.fxml"));
        Parent root = loader.load();

        Controller controller = loader.getController();

        primaryStage.getIcons().add(new Image("file:icon.png"));
        primaryStage.setTitle("Middleware");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();

        primaryStage.setOnCloseRequest(e -> {
            try {
                closeSmartCardConnection();
            } catch (Exception e1) {
                e1.printStackTrace();
            }
            Platform.exit();
            System.exit(0);
        });
    }

    @Override
    public void stop() throws Exception {
        super.stop();
        closeSmartCardConnection();
    }

    public static void main(String[] args) {
        launch(args);
    }
}

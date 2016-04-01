package MWGUI;

import Client.Client;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;

import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.ResourceBundle;

import static Client.Client.checkRevalidation;
import static Client.Client.requestRegistration;
import static Client.Client.sendPin;

public class Controller implements Initializable {

    @FXML
    public Button sendLogsButton;
    public PasswordField pwdFieldLogs;
    public Button pwdButtonLogs;
    public TextArea infoArea;
    public TextField responseStatus;
    @FXML
    private ComboBox<String> shopCombo;
    @FXML
    private Button registerButton;
    @FXML
    private PasswordField pwdField;
    @FXML
    private Button pwdButton;


    private String selectedShop = null;

    private DateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    @Override
    public void initialize(URL url, ResourceBundle rb) {// listen for changes to the fruit combo box selection and update the displayed fruit image accordingly.
        startClient();
        initRegister();
        initLog();


    }

    private void startClient() {
        try {
            Client.main(new String[]{""});
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initLog() {
        sendLogsButton.setDisable(true);
        infoArea.setDisable(true);


        pwdButtonLogs.setOnAction(event -> {
            String pwd = pwdField.getText();

            try {
                sendLogsButton.setDisable(false);
                infoArea.setDisable(false);
                pwdButtonLogs.setDisable(true);
                pwdFieldLogs.setDisable(true);
                sendPin();
            } catch (Exception e) {

                e.printStackTrace();
            }
        });

        sendLogsButton.setOnAction(event ->{
            try {
                int numberOfLogs = checkRevalidation(true);
                Date date = new Date();
                infoArea.appendText(dateFormat.format(date)+": Sending "+numberOfLogs+" logs to the LCP server\n");
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private void initRegister() {
        registerButton.setDisable(true);
        shopCombo.setDisable(true);


        pwdButton.setOnAction(event -> {
            String pwd = pwdField.getText();
            try {
                registerButton.setDisable(false);
                shopCombo.setDisable(false);
                pwdButton.setDisable(true);
                pwdField.setDisable(true);
                sendPin();

            } catch (Exception e) {
                e.printStackTrace();
            }
        });


        shopCombo.getSelectionModel().selectedItemProperty().addListener((selected, oldShop, newShop) -> {
            if (newShop != null) {
                selectedShop = newShop;
            }
        });

        registerButton.setOnAction(event -> {
            if (selectedShop != null) {
                Platform.runLater(() -> {
                    try {
                        boolean success = requestRegistration(selectedShop);
                        if(success){
                            responseStatus.setText("Registration of \""+selectedShop+"\" was succesful.\n");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            } else {
                //TODO notification
            }
        }

        );
    }

}

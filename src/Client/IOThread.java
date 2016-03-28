package Client;

import connection.SecureConnection;
import connection.SmartCardConnection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

import static Client.Client.c;

/**
 * Created by Gilles Callebaut on 25/03/2016.
 *
 */
public class IOThread extends Thread{

    private Socket socket = null;
    private ObjectInputStream in;
    private ObjectOutputStream out;

    public IOThread(Socket socket) {
        super("IOThread");
        System.out.println("IOThread started");
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            in = new ObjectInputStream(this.socket.getInputStream());
            out = new ObjectOutputStream(this.socket.getOutputStream());
            System.out.println("Waiting for requests.");
            String request;
            while ((request = (String)in.readObject()) != null) {
                processInput(request);
            }
            System.out.println("Stopping run method");
        }
        catch (IOException e) {
            System.out.println("Connection lost, shutting down thread.");
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    private void processInput(String request) throws Exception {
        System.out.println("Processing request: \""+request+"\"");
        switch (request) {
            case "changeLP":
            case "ChangeLP":
            case "changelp":
            case "Changelp":
                changeLP();
                break;
            default: {
                System.out.println("Request not recognized. Stopping connection ");
            }
        }
    }

    private void changeLP() throws Exception {
        String shopName = (String) in.readObject();
        System.out.println("------------------- setting up SECURE CONNECTION with "+shopName+" ---------------------");
        SecureConnection secureConnection = SecureConnection.setupSecureConnection(shopName,c);

        // 1. send pesudonym certificate for that shop
        byte[] encryptedPseudonymCertificate = SmartCardConnection.getPseudonymCertificateFromCard(shopName);
        secureConnection.send(encryptedPseudonymCertificate);

        // 2. receive amount for LP to change
        byte[] encryptedAmount = secureConnection.receiveBytes();

        // 3. change LP on SC
        byte[] encryptedResponse = SmartCardConnection.changeLP(shopName, encryptedAmount);

        // 4. send response back to shop
        secureConnection.send(encryptedResponse);
        secureConnection.close(c);
        System.out.println("------------------- SECURE CONNECTION with "+shopName+" is closed ---------------------");
    }
}

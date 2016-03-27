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
                processInput(request, in, out);
            }
            System.out.println("Stopping run method");
        }
        catch (IOException e) {
            System.out.println("Connection lost, shutting down thread.");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }


    private boolean processInput(String request, ObjectInputStream in,
                                 ObjectOutputStream out) throws Exception {
        System.out.println("Processing request: \""+request+"\"");
        switch (request) {
            case "changeLP":
            case "ChangeLP":
            case "changelp":
            case "Changelp":
                changeLP();
            default: {
                System.out.println("Request not recognized. Stopping connection ");
                return false;
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

        // 5. request number of transactions logged
        byte[] numberOfLogsInBytes = SmartCardConnection.getNumberOfLogs();

        // 6. if number is == 20 send to LCP secure
        short numberOfLogs = Util.readShort(numberOfLogsInBytes, 0);
        System.out.println("Number of transactions is "+numberOfLogs);
        if(numberOfLogs==20) SecureConnection.sendLogsToLCP();
        System.out.println("------------------- SECURE CONNECTION with "+shopName+" is closed ---------------------");
    }
}

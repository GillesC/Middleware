import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

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
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }

    }


    private boolean processInput(String request, ObjectInputStream in,
                                 ObjectOutputStream out)  {
        System.out.println("Processing request: \""+request+"\"");
        switch (request) {
            default: {
                System.out.println("Request not recognized. Stopping connection ");
                return false;
            }
        }
    }
}

package Client;

import com.sun.org.apache.xpath.internal.SourceTree;
import connection.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;


public class Client {

    public final static byte IDENTITY_CARD_CLA = (byte) 0x80;
    public static final byte VALIDATE_PIN_INS = 0x22;
    public final static short SW_VERIFICATION_FAILED = 0x6300;
    public final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

    public static final byte GET_SERIAL_INS = 0x24;
    public static final byte GET_NAME_INS = 0x26;

    public static final byte GET_EC_CERTIFICATE = 0x34;
    public static final byte CLEAR_OFFSET_INS = 0x35;
    public static final byte GENERATE_SESSION_KEY = 0x36;

    public static final byte ENCRYPT_BYTES_WITH_SESSION_KEY = 0x37;
    private static final byte DECRYPT_BYTES_WITH_SESSION_KEY = 0x39;

    public static final byte REGISTER_SHOP_PSEUDONYM = 0x38;
    public static final byte REGISTER_SHOP_CERTIFICATE = 0x39;
    public static final byte REGISTER_SHOP_NAME = 0x40;
    public static final byte REGISTER_SHOP_COMPLETE = 0x41;

    public static final byte CLOSE_SECURE_CONNECTION = 0x42;

    public static final byte MW_MUST_BE_AUTHENTICATED = (byte) 0xff;

    private static final byte TEST = 0x43;

    public static final byte INIT_CHALLENGE = 0x44;
    public static final byte CHALLENGE_ACCEPTED = 0x45;
    public static final byte GET_NEXT_CHALLENGE = 0x46;

    public static final byte GET_CURRENT_CHALLENGE = 0x47;

    public static final byte REGISTER_SHOP_CERTIFICATE_PART1 = 0x48;
    public static final byte REGISTER_SHOP_CERTIFICATE_PART2 = 0x49;
    public static final byte REGISTER_SHOP_CERTIFICATE_PART3 = 0x50;

    public static final byte GET_PSEUDONYM_CERTIFICATE_PART1 = 0x51;
    public static final byte GET_PSEUDONYM_CERTIFICATE_PART2 = 0x52;
    public static final byte GET_PSEUDONYM_CERTIFICATE_PART3 = 0x53;

    public static final byte SELECT_SHOP = 0x54;
    public static final byte CHANGE_LP = 0x55;

    public static final byte GET_NUMBER_OF_LOGS = 0x56;
    public static final byte GET_NEXT_LOG = 0x57;
    public static final byte CLEAR_LOGS = 0x58;

    public static final byte GET_LP = 0x59;


    public static final byte NO_SHOP_FOUND = (byte) 0xfd;


    private static final boolean isSimulation = false;

    public static IConnection c;


    public static void main(String[] args) throws Exception {

        if (isSimulation) {
            // Simulation:
            c = new SimulatedConnection();
        } else {
            // Real Card:
            c = new Connection();
            ((Connection) c).setTerminal(0); // depending on which cardreader you use
        }

        c.connect();

        try {
            /*
             * For more info on the use of CommandAPDU and ResponseAPDU: See
			 * http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/
			 * spec/index.html
			 */

            if (isSimulation) {
                simulationPreProcessing(c);
            }


            startServer();

            SmartCardConnection.setup(c);

            requestRegistration("Aldi");
            requestRegistration("Carrefour");


        } finally {
            //c.close(); // close the connection with the card
        }
    }


/*    private static void test() throws Exception {
        byte[] data = SmartCardConnection.sendAndReceive(TEST, (byte) 0x00, (byte) 0x00, new byte[]{0x01, 0x02, 0x03});
        Util.printBytes(data);
    }*/

    private static void requestRegistration(String shopName) throws Exception {
        SmartCardConnection.sendPin(new byte[]{0x01, 0x02, 0x03, 0x04});
        try {
            System.out.println("------------------- setting up SECURE CONNECTION with LCP ---------------------");
            SecureConnection secureConnection = SecureConnection.setupSecureConnection("LCP", c);


            byte[] encryptedShopName = SmartCardConnection.encrypt(shopName);
            //byte[] decryptedShopName = decryptOnSC(encryptedShopName);
            byte[] encryptedSerialNumber = SmartCardConnection.getSerialNumber();


            System.out.println("Sending \"RequestRegistration\" information");
            secureConnection.send("RequestRegistration");
            System.out.println("\t Sending encrypted Serial number");
            secureConnection.send(encryptedSerialNumber);
            System.out.println("\t Sending encrypted shopname");
            secureConnection.send(encryptedShopName);

            boolean existsAlready = (boolean) secureConnection.in();
            if (existsAlready) {
                System.err.println("Shop already on card, closing connection");
                secureConnection.close(c);
                System.out.println("------------------- SECURE CONNECTION with LCP is closed ---------------------");
                return;
            }

            //pseudonym for that particular shop
            System.out.println("\t Receiving encrypted pseudonym");
            byte[] encryptedPseudonym = secureConnection.receiveBytes();
            // Certificate signed by CA with pseudonym in for shop <shopname>
            System.out.println("\t Receiving encrypted certificate");
            byte[] encryptedCertificate = secureConnection.receiveBytes();

            SmartCardConnection.saveShopRegistration(encryptedPseudonym, encryptedCertificate, shopName);

            // close connection == sessionkey = null on SC
            secureConnection.close(c);
            System.out.println("------------------- SECURE CONNECTION with LCP is closed ---------------------");
        } catch (CertificateException certE) {
            System.err.println("CertificateException: " + certE.getMessage());
        }

    }

/*    private static byte[] decryptOnSC(byte[] encryptedData) throws Exception {
        System.out.println("Started decryption on SC");
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, DECRYPT_BYTES_WITH_SESSION_KEY, 0x00, 0x00, encryptedData, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Decrypt bytes with sessionkey failed " + r);

        System.out.println("\t\t Decrypted data:");
        Client.Util.printBytes(r.getData());

        System.out.println("Decrypted data in String format: "+new String(r.getData(), "UTF-8"));

        System.out.println("Ended decryption on SC");
        return r.getData();
    }*/


    public static boolean verify(byte[] data, PublicKey publicKey, byte[] sign) {
        Signature signer;
        try {
            signer = Signature.getInstance("SHA1withRSA");
            signer.initVerify(publicKey);
            signer.update(data);
            return (signer.verify(sign));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }


    private static void startServer() {
        new Thread(() -> {
            int portNumber = 13000;
            IOThread ioThread = null;
            try (ServerSocket serverSocket = new ServerSocket(portNumber)) {
                System.out.println("Server listening on port " + portNumber);
                while (true) {
                    ioThread = new IOThread(serverSocket.accept());
                    ioThread.start();
                }
            } catch (IOException e) {
                System.err.println("Could not listen on port " + portNumber);
                System.exit(-1);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();
    }

    private static void simulationPreProcessing(IConnection c) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;
        // 0. create applet (only for simulator!!!)
        // CommandAPDU(int cla, int ins, int p1, int p2, byte[] data,
        // int ne)
        // cla - the class byte CLA
        // ins - the instruction byte INS
        // p1 - the parameter byte P1
        // p2 - the parameter byte P2
        // ne - the maximum number of expected data bytes in a response
        // APDU

        a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
                new byte[]{(byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01}, 0x7f);
        r = c.transmit(a);
        System.out.println(r);
        if (r.getSW() != 0x9000)
            throw new Exception("select installer applet failed");

        a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,
                new byte[]{0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00},
                0x7f);
        r = c.transmit(a);
        System.out.println(r);
        if (r.getSW() != 0x9000)
            throw new Exception("Applet creation failed");

        // 1. Select applet (not required on a real card, applet is
        // selected by default)
        a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
                new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00}, 0x7f);
        r = c.transmit(a);
        System.out.println(r);
        if (r.getSW() != 0x9000)
            throw new Exception("Applet selection failed");
    }


    /*
    This method will check if there's a need for a revalidation
    If numOfLogs == 20 send logs to LCP server
    If this method is calledb by the GUI, send all logs to LCP
     */
    static void checkRevalidation(boolean callByGUI) throws Exception {
        System.out.println("-------------- Checking revalidation --------------");
        byte[] numberOfLogsInBytes = SmartCardConnection.getNumberOfLogs();
        // if number is == 20 send to LCP secure
        short numberOfLogs = Util.readShort(numberOfLogsInBytes, 0);
        System.out.println("Number of transactions is " + numberOfLogs);
        if (callByGUI) {
            if (!(numberOfLogs == 0)) {
                sendLogsToLCP(numberOfLogs);
            }
        } else if (numberOfLogs == 20) sendLogsToLCP(numberOfLogs);
        System.out.println("-------------- Ended revalidation --------------");
    }

    private static void sendLogsToLCP(int numOfLogs) throws Exception {
        new Thread(() -> {
            try {
                System.out.println("-------------- Sending logs to LCP server --------------");
                SecureConnection secureConnection = SecureConnection.setupSecureConnection("LCP", c);
                // 1. send commando "PushLogs"
                secureConnection.send("PushLogs");
                // 2. Ask all logs
                ArrayList<byte[]> logs = new ArrayList<>();
                for (int i = 0; i < numOfLogs; i++) {
                    System.out.println("\tGetting log number " + i);
                    byte[] log = SmartCardConnection.fetchNextLog();
                    if (log.length != 128) System.err.println("Wrong encrypted logsize, expected 128 bytes");
                    logs.add(log);
                }
                System.out.println("\tAll logs are received from the SC");

                // 3. Send logs to LCP server
                System.out.println("\tSending log ArrayList to LCP server");
                secureConnection.send(logs);

                // 4. Delete logs in SC
                System.out.println("\tClearing all logs from the SC");
                SmartCardConnection.clearLogs();

                // 5. Close secure connection with the LCP server
                secureConnection.close(c);
                System.out.println("-------------- Ended secure connection to send logs to LCP server --------------");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }).start();

    }

    //			/* generate random 20 bytes as challenge */
//			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//			byte[] bytesChallenge = new byte[20];
//			random.nextBytes(bytesChallenge);
//			System.out.print("Challenge (client): ");
//			printBytes(bytesChallenge);
//
//			// send command with randombytes
//			a = new CommandAPDU(IDENTITY_CARD_CLA, CHALLENGE_INS, 0x00, 0x00, bytesChallenge, 0xff);
//			ResponseAPDU sign = c.transmit(a);
//			System.out.print("Signature (received from card) : ");
//			printBytes(sign.getData());
//			if (sign.getSW() != 0x9000)
//				throw new Exception("Challenge request failed "+sign);
//			if (sign.getSW() == SW_PIN_VERIFICATION_REQUIRED)
//				throw new Exception("PIN verification is required");

//			// GET certificate from card
//			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//			// first 240
//			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_CERTIFICATE_INS, 0xf0, 0x00, 0xff);
//			r = c.transmit(a);
//			if (r.getSW() != 0x9000)
//				throw new Exception("240: Get certificate failed"+r);
//			if (r.getSW() == SW_PIN_VERIFICATION_REQUIRED)
//				throw new Exception("PIN verification is required");
//
//			outputStream.write(r.getData());
//
//			//next 209
//			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_CERTIFICATE_INS, 0xd1, 0x00, 0xff);
//			r = c.transmit(a);
//			if (r.getSW() != 0x9000)
//				throw new Exception("209: Get certificate failed"+r);
//			if (r.getSW() == SW_PIN_VERIFICATION_REQUIRED)
//				throw new Exception("PIN verification is required");
//			outputStream.write(r.getData());
//			byte[] cardCertificate = outputStream.toByteArray( );
//
//			CertificateFactory certFac = CertificateFactory.getInstance("X.509");
//			InputStream is = new ByteArrayInputStream(cardCertificate);
//			X509Certificate cert = (X509Certificate) certFac.generateCertificate(is);
//			// sign check (ALG_RSA_SHA_PKCS1)
//			Signature signature = Signature.getInstance("SHA1withRSA");
//			signature.initVerify(cert.getPublicKey());
//			signature.update(bytesChallenge);
//			boolean ok = signature.verify(sign.getData());
//			System.out.print("Verified? " + ok);
}

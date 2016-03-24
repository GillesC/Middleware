

import connection.Connection;
import connection.IConnection;
import connection.SecureConnection;
import connection.SimulatedConnection;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;


public class Client {

    private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
    private static final byte VALIDATE_PIN_INS = 0x22;
    private final static short SW_VERIFICATION_FAILED = 0x6300;
    private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

    private static final byte GET_SERIAL_INS = 0x24;
    private static final byte GET_NAME_INS = 0x26;

    private static final byte GET_EC_CERTIFICATE = 0x34;
    private static final byte CLEAR_OFFSET_INS = 0x35;
    private static final byte GENERATE_SESSION_KEY = 0x36;

    private static final byte ENCRYPT_BYTES_WITH_SESSION_KEY = 0x37;
    private static final byte DECRYPT_BYTES_WITH_SESSION_KEY = 0x39;

    private static final byte REGISTER_SHOP_PSEUDONYM = 0x38;
    private static final byte REGISTER_SHOP_CERTIFICATE = 0x39;
    private static final byte REGISTER_SHOP_NAME = 0x40;
    private static final byte REGISTER_SHOP_COMPLETE = 0x41;



    private static final boolean isSimulation = false;

    private static IConnection c;


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

            requestRegistration("Coolblue");

        } finally {
            c.close(); // close the connection with the card
        }
    }

    private static void requestRegistration(String shopName) throws Exception {
        sendPin(c);
        try {
            SecureConnection secureConnection = setupSecureConnection("LCP");

            byte[] encryptedShopName = encryptOnSC(shopName);
            //byte[] decryptedShopName = decryptOnSC(encryptedShopName);

            secureConnection.send("RequestRegistration");
            secureConnection.send(encryptedShopName);
            //pseudonym for that particular shop
            byte[] encryptedPseudonym = secureConnection.receiveBytes();
            // Certificate signed by CA with pseudonym in for shop <shopname>
            byte[] encryptedCertificate = secureConnection.receiveBytes();

            saveShopRegistrationToSC(encryptedPseudonym, encryptedCertificate, shopName);
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
        Util.printBytes(r.getData());

        System.out.println("Decrypted data in String format: "+new String(r.getData(), "UTF-8"));

        System.out.println("Ended decryption on SC");
        return r.getData();
    }*/

    private static void saveShopRegistrationToSC(byte[] encryptedPseudonym, byte[] encryptedCertificate, String shopName) throws Exception {
        System.out.println("Started saving registration for shop: " + shopName + " on SC");
        savePseudonymOnSC(encryptedPseudonym);
        saveCertificateOnSC(encryptedCertificate);
        saveShopNameOnSC(shopName);
        registryComplete();
        System.out.println("Ended registration of shop on SC");
    }

    private static void registryComplete() throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        // SC will make a new shop entry with given parameters
        a = new CommandAPDU(IDENTITY_CARD_CLA, REGISTER_SHOP_COMPLETE, 0x00, 0x00);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("REGISTER_SHOP_NAME failed " + r);
    }

    private static void saveShopNameOnSC(String shopName) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, REGISTER_SHOP_NAME, 0x00, 0x00, shopName.getBytes(StandardCharsets.UTF_8));
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("REGISTER_SHOP_NAME failed " + r);
    }

    private static void saveCertificateOnSC(byte[] encryptedCertificate) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, REGISTER_SHOP_CERTIFICATE, 0x00, 0x00, encryptedCertificate);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("REGISTER_SHOP_CERTIFICATE failed " + r);
    }

    private static void savePseudonymOnSC(byte[] encryptedPseudonym) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, REGISTER_SHOP_PSEUDONYM, 0x00, 0x00, encryptedPseudonym);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("REGISTER_SHOP_PSEUDONYM failed " + r);
    }


    private static byte[] encryptOnSC(String shopName) throws Exception {
        System.out.println("Started encryption on SC");
        CommandAPDU a;
        ResponseAPDU r;

        byte[] shopInBytes = shopName.getBytes(StandardCharsets.UTF_8);
        System.out.println("\t\t Shop in bytes:");Util.printBytes(shopInBytes);
        a = new CommandAPDU(IDENTITY_CARD_CLA, ENCRYPT_BYTES_WITH_SESSION_KEY, 0x00, 0x00,shopInBytes , 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Encrypt bytes with sessionkey failed " + r);

        System.out.println("\t\t Encrypted data:");
        Util.printBytes(r.getData());

        System.out.println("Ended encryption on SC");
        return r.getData();
    }





    private static SecureConnection setupSecureConnection(String with) throws Exception {
        SecureConnection secureConnection = new SecureConnection();
        secureConnection.with("localhost", with);

        byte[] LCPECCertificate = secureConnection.getECCertificate();

        /* Sending Card EC certificate */
        System.out.println("\nGetting publicECKey from JavaCard");
        byte[] cardECCertificate = getECCertificateFromCard();
        System.out.println("Sending EC certificate...");
        secureConnection.send(cardECCertificate);
        System.out.println("Done sending");

        byte[] ecPublicKeyOtherPartyBytes = SecurityUtil.getECPublicKeyFromCertificate(LCPECCertificate, SecureConnection.LCP_NAME);
        generateSessionKey(ecPublicKeyOtherPartyBytes);

        System.out.println("\nSecure Connection has been setup");
        return secureConnection;
    }




    private static void generateSessionKey(byte[] publicKeyOtherPartyBytes) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, GENERATE_SESSION_KEY, 0x00, 0x00, publicKeyOtherPartyBytes, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Generate SessionKey failed " + r);

        System.out.println("ONLY IN DEBUG: Received sessionkey: ");
        Util.printBytes(r.getData());
    }

    private static byte[] getECCertificateFromCard() throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CLEAR_OFFSET_INS, 0xf0, 0x00, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Get certificate failed " + r);


        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        a = new CommandAPDU(IDENTITY_CARD_CLA, GET_EC_CERTIFICATE, 0xf0, 0x00, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Get certificate failed " + r);
        outputStream.write(r.getData());
        a = new CommandAPDU(IDENTITY_CARD_CLA, GET_EC_CERTIFICATE, 0xf0, 0x00, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Get certificate failed " + r);
        outputStream.write(r.getData());
        a = new CommandAPDU(IDENTITY_CARD_CLA, GET_EC_CERTIFICATE, 0x6b, 0x00, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Get certificate failed " + r);
        outputStream.write(r.getData());

        return outputStream.toByteArray();
    }

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

    private static void sendPin(IConnection c) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;
        // 2. Send PIN
        a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, new byte[]{0x01, 0x02, 0x03, 0x04});
        r = c.transmit(a);
        System.out.println(r);
        if (r.getSW() == SW_VERIFICATION_FAILED)
            throw new Exception("PIN INVALID");
        else if (r.getSW() != 0x9000)
            throw new Exception("Exception on the card: " + r.getSW());
        System.out.println("PIN Verified");

        // 3. request serial number of card
        a = new CommandAPDU(IDENTITY_CARD_CLA, GET_SERIAL_INS, 0x00, 0x00, 0x03);
        r = c.transmit(a);
        System.out.println(r);
        if (r.getSW() == SW_PIN_VERIFICATION_REQUIRED)
            throw new Exception("PIN verification is required");
        if (r.getSW() != 0x9000)
            throw new Exception("Serial Number request failed " + r.getSW());
        System.out.print("Serial ID : ");
        Util.printBytes(r.getData());

        // 4. getName
        a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00, 0xff);
        r = c.transmit(a);
        System.out.print("Name : ");
        Util.printBytes(r.getData());
        if (r.getSW() != 0x9000)
            throw new Exception("Name request failed");
        if (r.getSW() == SW_PIN_VERIFICATION_REQUIRED)
            throw new Exception("PIN verification is required");
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

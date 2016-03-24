

import connection.Connection;
import connection.IConnection;
import connection.SecureConnection;
import connection.SimulatedConnection;
import sun.security.ec.ECPublicKeyImpl;
import sun.security.x509.X500Name;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;


public class Client {

    private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
    private static final byte VALIDATE_PIN_INS = 0x22;
    private final static short SW_VERIFICATION_FAILED = 0x6300;
    private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

    private static final byte GET_SERIAL_INS = 0x24;
    private static final byte GET_NAME_INS = 0x26;
    //private static final byte CHALLENGE_INS = 0x28;
    //private static final byte GET_CERTIFICATE_INS = 0x30;
    //private static final byte GET_CERTIFICATE_SIZE_INS = 0x32;

    private static final byte GET_EC_CERTIFICATE = 0x34;
    private static final byte CLEAR_OFFSET_INS = 0x35;
    private static final byte GENERATE_SESSION_KEY = 0x36;

    //private static final byte SET = 0x37;
    //private static final byte PULL = 0x38;

    private static final byte ENCRYPT_BYTES_WITH_SESSION_KEY = 0x37;

    private static final boolean isSimulation = false;

    private static PrivateKey privateKeyCA;
    private static PublicKey publicKeyCA;

    private static IConnection c;


    public static void main(String[] args) throws Exception {

        if (isSimulation) {
            // Simulation:
            c = new SimulatedConnection();
        } else {
            // Real Card:
            c = new Connection();
            ((Connection) c).setTerminal(0); // depending on which cardreader
            // you use
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

            /* test persistance storage */
            /*
            CommandAPDU a;
            ResponseAPDU r;

            a = new CommandAPDU(IDENTITY_CARD_CLA, SET, 0x00, 0x00, new byte[] {0x66}, 0xff);
            r = c.transmit(a);
            if (r.getSW() != 0x9000)
                throw new Exception("test failed "+r);


           a = new CommandAPDU(IDENTITY_CARD_CLA, PULL, 0x00, 0x00, 0xff);
            r = c.transmit(a);
            if (r.getSW() != 0x9000)
                throw new Exception("Pull test data "+r);
                printBytes(r.getData());
                */

            loadCACertificate();

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
            //secureConnection.send("RequestRegistration");
            //secureConnection.send(encryptedShopName);
            //pseudonym for that particular shop
            //byte[] encryptedPseudonym = secureConnection.receiveBytes();
            // Certificate signed by CA with pseudonym in for shop <shopname>
            //byte[] encryptedCertificate = secureConnection.receiveBytes();

            //saveShopRegistrationToSC(encryptedPseudonym, encryptedCertificate, shortToByte(0), shopName);
        } catch (CertificateException certE) {
            System.err.println("CertificateException: " + certE.getMessage());
        }

    }
/*
    private static void saveShopRegistrationToSC(byte[] encryptedPseudonym, byte[] encryptedCertificate, byte LP, String shopName) throws Exception {
        System.out.println("Started saving registration for shop: " + shopName + " on SC");
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, REGISTER_SHOP, 0x00, 0x00, shopName.getBytes(StandardCharsets.UTF_8), 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Encrypt bytes with sessionkey failed " + r);

        System.out.println("\t\t Encrypted data:");
        printBytes(r.getData());

        System.out.println("Ended registration of shop on SC");
    }
    */


    private static byte[] encryptOnSC(String shopName) throws Exception {
        System.out.println("Started encryption on SC");
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, ENCRYPT_BYTES_WITH_SESSION_KEY, 0x00, 0x00, shopName.getBytes(StandardCharsets.UTF_8), 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Encrypt bytes with sessionkey failed " + r);

        System.out.println("\t\t Encrypted data:");
        printBytes(r.getData());

        System.out.println("Ended encryption on SC");
        return r.getData();
    }


    private static void loadCACertificate() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String fileNameStore1 = new File("certificates\\LCP.jks").getAbsolutePath();
        char[] password = "LCP".toCharArray();
        FileInputStream fis = new FileInputStream(fileNameStore1);
        keyStore.load(fis, password);
        fis.close();

        privateKeyCA = (PrivateKey) keyStore.getKey("LoyaltyCardProvider", "LCP".toCharArray());
        java.security.cert.Certificate certCA = keyStore.getCertificate("LoyaltyCardProvider");
        publicKeyCA = certCA.getPublicKey();
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

        byte[] ecPublicKeyOtherPartyBytes = getECPublicKeyFromCertificate(LCPECCertificate, SecureConnection.LCP_NAME);
        generateSessionKey(ecPublicKeyOtherPartyBytes);

        System.out.println("\nSecure Connection has been setup");
        return secureConnection;
    }

    private static byte[] getECPublicKeyFromCertificate(byte[] lcpecCertificate, String subjectName) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        	/* Create cert + get public key */
        X509Certificate certificateOtherParty = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream byteInputStream = new ByteArrayInputStream(lcpecCertificate);
            certificateOtherParty = (X509Certificate) certFactory.generateCertificate(byteInputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        checkCertificate(certificateOtherParty, subjectName);

        PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();
        ECPublicKeyImpl ecPublicKeyOtherParty = (ECPublicKeyImpl) publicKeyOtherParty;
        byte[] ecPublicKeyOtherPartyBytes = ecPublicKeyOtherParty.getEncodedPublicValue();
        System.out.println("Public key other party (length): " + ecPublicKeyOtherPartyBytes.length);
        printBytes(ecPublicKeyOtherPartyBytes);
        return ecPublicKeyOtherPartyBytes;
    }

    private static void checkCertificate(X509Certificate cert, String subjectName) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (cert != null) {
            cert.checkValidity(new Date());
            cert.verify(publicKeyCA);
            if (!SecureConnection.checkName(cert, subjectName)) {
                System.err.println("SubjectName doesn't match contacted name...");
            }
        } else {
            System.err.println("ECCertificate is null...");
        }

        //TODO check OCSP
    }


    private static void generateSessionKey(byte[] publicKeyOtherPartyBytes) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, GENERATE_SESSION_KEY, 0x00, 0x00, publicKeyOtherPartyBytes, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Generate SessionKey failed " + r);

        System.out.println("ONLY IN DEBUG: Received sessionkey: ");
        printBytes(r.getData());
    }

    private static byte[] getECCertificateFromCard() throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

//		/* Ask for certificate length */
//        a = new CommandAPDU(IDENTITY_CARD_CLA, GET_EC_CERTIFICATE_SIZE, 0x00, 0x00, 0xff);
//		r = c.transmit(a);
//		if (r.getSW() != 0x9000)
//			throw new Exception("Get certificate size failed "+r);
//		if (r.getSW() == SW_PIN_VERIFICATION_REQUIRED)
//			throw new Exception("PIN verification is required");
//		
//		short certificateLength = readShort(r.getData(),0);

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

    private static byte shortToByte(int i) {
        return (byte) (((short) i >> 8) & 0xff);
    }

    private static void printBytes(byte[] data) {
        String sb1 = "";
        for (byte b : data) {
            sb1 += "0x" + String.format("%02x", b) + " ";
        }
        System.out.println(sb1);

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

    public static short readShort(byte[] data, int offset) {
        return (short) (((data[offset] << 8)) | ((data[offset + 1] & 0xff)));
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
        printBytes(r.getData());

        // 4. getName
        a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00, 0xff);
        r = c.transmit(a);
        System.out.print("Name : ");
        printBytes(r.getData());
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

package connection;

import Client.Keys;
import Client.Util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import static Client.Client.*;

/**
 * Created by Gilles Callebaut on 25/03/2016.
 *
 */
public class SmartCardConnection {

    private static IConnection c;
    private static byte challengeP1;
    private static byte challengeP2;



    private static byte[] decryptWithPrivateKey(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher asymCipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

        asymCipher.init(Cipher.DECRYPT_MODE, Keys.getMyPrivateRSAKey());
        return asymCipher.doFinal(data);
    }

    public static byte[] encryptWithPublicKeySC(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("Data to encrypt: ");

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher asymCipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

        asymCipher.init(Cipher.ENCRYPT_MODE, Keys.getPublicSCKey());

        byte[] encryptedData = asymCipher.doFinal(data);

        System.out.println("Data encrypted (length "+encryptedData.length+"): ");
        Util.printBytes(encryptedData);

        return encryptedData;
    }

    public static void setup(IConnection c) {
        SmartCardConnection.c = c;
    }


    public static void setNextChallenge(byte[] nextChallenge) {
        SmartCardConnection.challengeP1 = nextChallenge[0];
        SmartCardConnection.challengeP2 = nextChallenge[1];
    }

    public static void sendPin(byte[] pin) throws Exception {
        //FIRST AUTHENTICATE
        authenticate();
        byte[] encryptedPin = SmartCardConnection.encryptWithPublicKeySC(pin);

        CommandAPDU a;
        ResponseAPDU r;
        // 2. Send PIN
        a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, encryptedPin);
        r = c.transmit(a);
        System.out.println(r);
        if (r.getSW() == SW_VERIFICATION_FAILED)
            throw new Exception("PIN INVALID");
        else if (r.getSW() != 0x9000)
            throw new Exception("Exception on the card: " + r.getSW());
        System.out.println("PIN Verified");
    }

    private static void authenticate() throws Exception {
        byte[] challenge = SmartCardConnection.sendInsAndReceive(INIT_CHALLENGE, (byte) 0x00, (byte) 0x00, true);
        System.out.println("Challenge: "); Util.printBytes(challenge);
        byte[] nextChallenge = SmartCardConnection.sendDataAndReceive(CHALLENGE_ACCEPTED,(byte) 0x00, (byte) 0x00, challenge, true);
        if(nextChallenge.length!=2) System.err.println("Next challenge has to be 2 bytes long");
        else SmartCardConnection.setNextChallenge(nextChallenge);
        System.out.println("NextChallenge: "); Util.printBytes(nextChallenge);
    }

    /* this is a secure command thus the challenges needs to be included in the parameters */
    public static void generateSessionKey(byte[] publicKeyOtherPartyBytes) throws Exception {
        sendDataWithChallengeAndReceive(GENERATE_SESSION_KEY, publicKeyOtherPartyBytes, false);
    }

    private static void fetchNextChallenge() throws Exception {
        byte[] nextChallenge = SmartCardConnection.sendInsAndReceive(GET_NEXT_CHALLENGE,(byte) 0x00, (byte) 0x00,true);
        if(nextChallenge.length!=2) System.err.println("Next challenge has to be 2 bytes long");
        else SmartCardConnection.setNextChallenge(nextChallenge);
        //System.out.println("NextChallenge: "); Util.printBytes(nextChallenge);
    }

    public static byte[] getECCertificateFromCard() throws Exception {
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

    /* this is a secure command thus the challenges needs to be included in the parameters */
    public static byte[] getSerialNumber() throws Exception {
        System.out.println("Get serial number from card encrypted with sessionkey");
        byte[] encryptedSerialNumber = sendInsWithChallengeAndReceiveSessionData(GET_SERIAL_INS);
        System.out.println("encryptedSerialNumber"); Util.printBytes(encryptedSerialNumber);
        return encryptedSerialNumber;
    }



    public static void registryComplete() throws Exception {
        sendInsWithChallenge(REGISTER_SHOP_COMPLETE);
    }

    private static void saveShopName(String shopName) throws Exception {
        sendDataWithChallenge(REGISTER_SHOP_NAME, shopName.getBytes(StandardCharsets.UTF_8));
    }

    /* saving certificate for pseudonym
    Length encrypted = 416
    Length decrypted = 413
     */
    private static void saveCertificate(byte[] encryptedCertificate) throws Exception {
        if(encryptedCertificate.length!=512) System.err.println("Wrong encrypted certificate size");
        System.out.println("\t Sending first part");
        byte[] certPart1 = new byte[200];
        System.arraycopy(encryptedCertificate, 0, certPart1, 0, 200);
        sendDataWithChallenge(REGISTER_SHOP_CERTIFICATE_PART1, certPart1);
        System.out.println("\t Sending second part");
        byte[] certPart2 = new byte[200];
        System.arraycopy(encryptedCertificate, 200, certPart2, 0, 200);
        sendDataWithChallenge(REGISTER_SHOP_CERTIFICATE_PART2, certPart2);
        System.out.println("\t Sending last part");
        byte[] certPart3 = new byte[112];
        System.arraycopy(encryptedCertificate, 400, certPart3, 0, 112);
        sendDataWithChallenge(REGISTER_SHOP_CERTIFICATE_PART3, certPart3);
        //System.out.println("Length of decrypted cert: "+Util.readShort(length, 0));

        //sendDataWithChallenge(REGISTER_SHOP_CERTIFICATE, encryptedCertificate);
    }

    private static void savePseudonym(byte[] encryptedPseudonym) throws Exception {
        byte[] pseudo = sendDataWithChallengeAndReceive(REGISTER_SHOP_PSEUDONYM, encryptedPseudonym,true);
        System.out.println("Saved pseudo is "+new String(pseudo));

    }


    public static byte[] encrypt(String shopName) throws Exception {
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

    public static void saveShopRegistration(byte[] encryptedPseudonym, byte[] encryptedCertificate, String shopName) throws Exception {
        System.out.println("Started saving registration for shop: " + shopName + " on SC");
        System.out.println("\t Saving psuedonym");
        SmartCardConnection.savePseudonym(encryptedPseudonym);
        System.out.println("\t Saving certificate");
        SmartCardConnection.saveCertificate(encryptedCertificate);
        System.out.println("\t Saving shopname");
        SmartCardConnection.saveShopName(shopName);
        SmartCardConnection.registryComplete();
        System.out.println("Ended registration of shop on SC");
    }



    /************** SEND AND RECEIVE METHODS *************************/
    public static void sendIns(byte CMD, byte p1, byte p2) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r);
    }


    public static void sendData(byte CMD, byte p1, byte p2, byte[] data) throws Exception {
        System.out.println("Send data (length "+data.length+"): "); Util.printBytes(data);

        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, data, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r);
    }

    private static byte[]  sendInsAndReceive(byte CMD, boolean encryptedMW) throws Exception {
        return sendInsAndReceive(CMD, (byte) 0x00, (byte) 0x00, encryptedMW);
    }

    private static byte[] sendInsAndReceive(byte CMD, byte p1, byte p2, boolean encryptedMW) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        //System.out.println("Send instruction: [CMD "+CMD+" p1 "+p1+" p2 "+p2+"]");
        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r +" SW: "+r.getSW());

        //System.out.println("Received encrypted data (length "+r.getData().length+"): "); Util.printBytes(r.getData());
        if(encryptedMW) return decryptWithPrivateKey(r.getData());
        else return r.getData();
    }



    private static byte[] sendDataAndReceive(byte CMD, byte p1, byte p2, byte[] data, boolean encryptedMW) throws Exception {
        //byte[] dataToSend = encryptWithPublicKeySC(data);
        byte[] dataToSend = data;
        System.out.println("Send data: "); Util.printBytes(data);

        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, dataToSend, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r);

        System.out.println("Received data (length "+r.getData().length+"): "); Util.printBytes(r.getData());
        if(encryptedMW) return decryptWithPrivateKey(r.getData());
        else return r.getData();
    }

    private static void sendInsWithChallenge(byte CMD) throws Exception {
        sendIns(CMD,challengeP1,challengeP2);
    }

    private static byte[] sendInsWithChallengeAndReceiveSessionData(byte CMD) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        System.out.println("Send instruction: [CMD "+CMD+" p1 "+challengeP1+" p2 "+challengeP2+"]");
        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, challengeP1, challengeP2, new byte[]{0x00}, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r +" SW: "+r.getSW());

        System.out.println("Received data (length "+r.getData().length+"): "); Util.printBytes(r.getData());
        return r.getData();
    }

    private static byte[] sendInsAndReceiveAndReceive(byte cmd, byte p1, byte p2, boolean encryptedMW) throws Exception {
        return sendInsAndReceive(cmd, p1, p2, encryptedMW);
    }

    private static byte[] sendDataWithChallengeAndReceive(byte CMD, byte[] data, boolean encryptedMW) throws Exception {
        byte[] d = sendDataAndReceive(CMD, challengeP1, challengeP2, data, encryptedMW);
        fetchNextChallenge();
        return d;
    }

    private static void sendDataWithChallenge(byte CMD, byte[] data) throws Exception {
        sendData(CMD, challengeP1, challengeP2, data);
        fetchNextChallenge();
    }

    public static byte[] getPseudonymCertificateFromCard(String shopName) throws Exception {
        byte[] shopNameInBytes = shopName.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedCertificatePart1 = sendDataWithChallengeAndReceive(GET_PSEUDONYM_CERTIFICATE_PART1,shopNameInBytes , false);
        if(encryptedCertificatePart1.length!=200) System.err.println("Wrong certificate size!");
        byte[] encryptedCertificatePart2 = sendDataWithChallengeAndReceive(GET_PSEUDONYM_CERTIFICATE_PART2,shopNameInBytes , false);
        if(encryptedCertificatePart2.length!=200) System.err.println("Wrong certificate size!");
        byte[] encryptedCertificatePart3 = sendDataWithChallengeAndReceive(GET_PSEUDONYM_CERTIFICATE_PART3,shopNameInBytes , false);
        if(encryptedCertificatePart3.length!=112) System.err.println("Wrong certificate size!");

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(encryptedCertificatePart1);
        outputStream.write(encryptedCertificatePart2);
        outputStream.write(encryptedCertificatePart3);

        return outputStream.toByteArray();
    }

    public static byte[] changeLP(String shopName, byte[] encryptedAmount) throws Exception {
        byte[] shopNameInBytes = shopName.getBytes(StandardCharsets.UTF_8);
        // 1. select shop: card wil iterate through shopEntries and load the selected shopEntry
        // this will be loaded automatically when getPseudonymCertificateFromCard is called
        // so there is no need to do this again
        //sendDataWithChallenge(SELECT_SHOP, shopNameInBytes);

        // 2. changeLP with <amount> return: encrypted succeeded msg (0x00) otherwise failed
        return sendDataWithChallengeAndReceive(CHANGE_LP, encryptedAmount, false);
    }

    public static byte[] getNumberOfLogs() throws Exception {
        return sendInsAndReceive(GET_NUMBER_OF_LOGS, false);
    }

    public static byte[] fetchNextLog() throws Exception {
        return sendInsWithChallengeAndReceiveSessionData(GET_NEXT_LOG);
    }

    public static void clearLogs() throws Exception {
        sendInsWithChallenge(CLEAR_LOGS);
    }
}

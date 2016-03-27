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
    public static byte challengeP1;
    public static byte challengeP2;

    public static void sendIns(byte CMD, byte p1, byte p2) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r);
    }


    public static void sendData(byte CMD, byte p1, byte p2, byte[] data) throws Exception {
        System.out.println("Send data: "); Util.printBytes(data);

        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, data, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r);
    }

    public static byte[] sendInsAndReceive(byte CMD, byte p1, byte p2) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        System.out.println("Send instruction: [CMD "+CMD+" p1 "+p1+" p2 "+p2+"]");
        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r +" SW: "+r.getSW());

        System.out.println("Received encrypted data (length "+r.getData().length+"): "); Util.printBytes(r.getData());
        return decryptWithPrivateKey(r.getData());
    }



    public static byte[] sendDataAndReceive(byte CMD, byte p1, byte p2, byte[] data) throws Exception {
        //byte[] dataToSend = encryptWithPublicKeySC(data);
        byte[] dataToSend = data;
        System.out.println("Send data: "); Util.printBytes(data);

        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, dataToSend, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r);

        System.out.println("Received encrypted data (length "+r.getData().length+"): "); Util.printBytes(r.getData());
        return decryptWithPrivateKey(r.getData());
    }

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

        /*// 4. getName
        a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00, 0xff);
        r = c.transmit(a);
        System.out.print("Name : ");
        Util.printBytes(r.getData());
        if (r.getSW() != 0x9000)
            throw new Exception("Name request failed");
        if (r.getSW() == SW_PIN_VERIFICATION_REQUIRED)
            throw new Exception("PIN verification is required");*/
    }

    private static void authenticate() throws Exception {
        byte[] challenge = SmartCardConnection.sendInsAndReceive(INIT_CHALLENGE, (byte) 0x00, (byte) 0x00);
        System.out.println("Challenge: "); Util.printBytes(challenge);
        byte[] nextChallenge = SmartCardConnection.sendDataAndReceive(CHALLENGE_ACCEPTED,(byte) 0x00, (byte) 0x00, challenge);
        if(nextChallenge.length!=2) System.err.println("Next challenge has to be 2 bytes long");
        else SmartCardConnection.setNextChallenge(nextChallenge);
        System.out.println("NextChallenge: "); Util.printBytes(nextChallenge);
    }

    /* this is a secure command thus the challenges needs to be included in the parameters */
    public static void generateSessionKey(byte[] publicKeyOtherPartyBytes) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, GENERATE_SESSION_KEY, challengeP1, challengeP2, publicKeyOtherPartyBytes, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("Generate SessionKey failed " + r);

        System.out.println("ONLY IN DEBUG: Received sessionkey: ");
        Util.printBytes(r.getData());

        fetchNextChallenge();
    }

    private static void fetchNextChallenge() throws Exception {
        byte[] nextChallenge = SmartCardConnection.sendInsAndReceive(GET_NEXT_CHALLENGE,(byte) 0x00, (byte) 0x00);
        if(nextChallenge.length!=2) System.err.println("Next challenge has to be 2 bytes long");
        else SmartCardConnection.setNextChallenge(nextChallenge);
        System.out.println("NextChallenge: "); Util.printBytes(nextChallenge);
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
        byte[] encryptedSerialNumber = sendSecureInsAndReceiveSessionData(GET_SERIAL_INS, challengeP1, challengeP2);
        System.out.println("Return values"); Util.printBytes(encryptedSerialNumber);
        fetchNextChallenge();
        return encryptedSerialNumber;
    }

    private static byte[] sendSecureInsAndReceiveSessionData(byte CMD, byte p1, byte p2) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, new byte[]{0x00}, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r +" SW: "+r.getSW());

        System.out.println("Received encrypted data (length "+r.getData().length+"): "); Util.printBytes(r.getData());
        return r.getData();
    }

    private static byte[] sendSecureInsAndReceive(byte CMD, byte p1, byte p2) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, new byte[]{0x00}, 0xff);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r +" SW: "+r.getSW());

        System.out.println("Received encrypted data (length "+r.getData().length+"): "); Util.printBytes(r.getData());
        return decryptWithPrivateKey(r.getData());
    }


    public static void registryComplete() throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        // SC will make a new shop entry with given parameters
        a = new CommandAPDU(IDENTITY_CARD_CLA, REGISTER_SHOP_COMPLETE, 0x00, 0x00);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("REGISTER_SHOP_NAME failed " + r);
    }

    public static void saveShopName(String shopName) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, REGISTER_SHOP_NAME, 0x00, 0x00, shopName.getBytes(StandardCharsets.UTF_8));
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("REGISTER_SHOP_NAME failed " + r);
    }

    public static void saveCertificate(byte[] encryptedCertificate) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, REGISTER_SHOP_CERTIFICATE, 0x00, 0x00, encryptedCertificate);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("REGISTER_SHOP_CERTIFICATE failed " + r);
    }

    public static void savePseudonym(byte[] encryptedPseudonym) throws Exception {
        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, REGISTER_SHOP_PSEUDONYM, 0x00, 0x00, encryptedPseudonym);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("REGISTER_SHOP_PSEUDONYM failed " + r);
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
        SmartCardConnection.savePseudonym(encryptedPseudonym);
        SmartCardConnection.saveCertificate(encryptedCertificate);
        SmartCardConnection.saveShopName(shopName);
        SmartCardConnection.registryComplete();
        System.out.println("Ended registration of shop on SC");
    }

}

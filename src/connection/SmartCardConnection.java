package connection;

import Client.Keys;
import Client.SecurityUtil;
import Client.Util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import static Client.Client.IDENTITY_CARD_CLA;

/**
 * Created by Gilles Callebaut on 25/03/2016.
 *
 */
public class SmartCardConnection {
    private static IConnection c;

    public static void send() {

    }

    public static byte[] sendAndReceive(byte CMD, byte p1, byte p2, byte[] data, int returnBytes) throws Exception {
        byte[] dataToSend = encryptWithPublicKeySC(data);

        CommandAPDU a;
        ResponseAPDU r;

        a = new CommandAPDU(IDENTITY_CARD_CLA, CMD, p1, p2, dataToSend, returnBytes);
        r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception(CMD+" failed " + r);

        System.out.println("Received encrypted data: "); Util.printBytes(r.getData());
        return decryptWithPrivateKey(r.getData());
    }

    private static byte[] decryptWithPrivateKey(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        data = Arrays.copyOf(data, 64);
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Cipher asymCipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

        asymCipher.init(Cipher.DECRYPT_MODE, Keys.getMyPrivateRSAKey());
        return asymCipher.doFinal(data);
    }

    private static byte[] encryptWithPublicKeySC(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("Data to encrypt: ");
        Util.printBytes(data);

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


}

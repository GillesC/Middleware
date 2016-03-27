package Client;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by Gilles Callebaut on 25/03/2016.
 */
public class RSAGeneration {

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException {

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);

        KeyPair keyPair = keyGen.generateKeyPair();

        RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privKey = (RSAPrivateKey) keyPair.getPrivate();

        System.out.println("Extracting exponents and modulus's");
        System.out.print("byte[] privExponent = new byte[]{");
        for (byte b : privKey.getPrivateExponent().toByteArray()) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println("};");
        System.out.println("Length: "+privKey.getPrivateExponent().toByteArray().length);

        System.out.print("byte[] privModulus = new byte[]{");
        for (byte b : privKey.getModulus().toByteArray()) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println("};");
        System.out.println("Length: "+privKey.getModulus().toByteArray().length);

        System.out.print("byte[] pubExponent = new byte[]{");
        for (byte b : pubKey.getPublicExponent().toByteArray()) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println("};");
        System.out.println("Length: "+pubKey.getPublicExponent().toByteArray().length);

        System.out.print("byte[] pubModulus = new byte[]{");
        for (byte b : privKey.getModulus().toByteArray()) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println("};");
        System.out.println("Length: "+privKey.getModulus().toByteArray().length);


        System.out.print("byte[] pubKeySc = new byte[]{");
        for (byte b : pubKey.getEncoded()) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println("};");
        System.out.println("Length: "+pubKey.getEncoded().length);

        System.out.print("byte[] privKeyMW = new byte[]{");
        for (byte b : privKey.getEncoded()) {
            System.out.print("(byte) 0x" + String.format("%02x", b) + ", ");
        }
        System.out.println("};");
        System.out.println("Length: "+privKey.getEncoded().length);

    }
}

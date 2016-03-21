

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import connection.Connection;
import connection.IConnection;
import connection.SimulatedConnection;
import sun.security.ec.ECPublicKeyImpl;


public class Client {

	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	private static final byte GET_SERIAL_INS = 0x24;
	private static final byte GET_NAME_INS = 0x26;
	private static final byte CHALLENGE_INS = 0x28;
	private static final byte GET_CERTIFICATE_INS = 0x30;
	private static final byte GET_CERTIFICATE_SIZE_INS = 0x32;
	
	private static final byte GET_EC_CERTIFICATE = 0x34;	
	private static final byte CLEAR_OFFSET_INS = 0x35;
	private static final byte GENERATE_SESSION_KEY = 0x36;

	private static final boolean isSimulation = false;
	

	public static void main(String[] args) throws Exception {
		IConnection c;

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

			CommandAPDU a;
			ResponseAPDU r;

			if (isSimulation) {
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
						new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01 }, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW() != 0x9000)
					throw new Exception("select installer applet failed");

				a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,
						new byte[] { 0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00 },
						0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW() != 0x9000)
					throw new Exception("Applet creation failed");

				// 1. Select applet (not required on a real card, applet is
				// selected by default)
				a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
						new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 }, 0x7f);
				r = c.transmit(a);
				System.out.println(r);
				if (r.getSW() != 0x9000)
					throw new Exception("Applet selection failed");
			}

			// 2. Send PIN
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, new byte[] { 0x01, 0x02, 0x03, 0x04 });
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
			
			
			setupSecureConnection(c);
			

		} catch (Exception e) {
			throw e;
		} finally {
			c.close(); // close the connection with the card
		}
	}

	private static void setupSecureConnection(IConnection c) throws Exception {
		String hostName = "localhost";
		int portNumber = 15151;

		try (
            Socket socket = new Socket(hostName, portNumber);
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        ) {
            System.out.println("Trying to write to server");
            out.writeObject("SetupSecureConnection");
            System.out.println("Wrote to server");

            /* Getting LCP EC Certificate */
            byte[] LCPECCertificate = (byte[])in.readObject();
            System.out.println("Received certificate");
            for (byte b: LCPECCertificate) {
                System.out.print("0x" + String.format("%02x", b) + " ");
            }
            
            /* Sending Card EC certificate */
            System.out.println("\nGetting publicECKey from JavaCard");
            byte[] cardECCertificate = getECCertificateFromCard(c);
            
            System.out.println("Sending EC certificate...");
    		out.writeObject(cardECCertificate);
    		System.out.println("Done sending");
    		
    		/* Create cert + get public key */
    		X509Certificate certificateOtherParty = null;
            try {
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                InputStream byteInputStream = new ByteArrayInputStream(LCPECCertificate);
                certificateOtherParty = (X509Certificate)certFactory.generateCertificate(byteInputStream);
            } catch (CertificateException e) {
                e.printStackTrace();
            }
            ECPublicKey pubCEKey = (ECPublicKey) certificateOtherParty.getPublicKey();
            //ECPublicKey pubCEKey = (ECPublicKey) publicKeyOtherParty;
			PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();
			ECPublicKeyImpl ecPublicKeyOtherParty = (ECPublicKeyImpl)publicKeyOtherParty;
			byte[] ecPublicKeyOtherPartyBytes = ecPublicKeyOtherParty.getEncodedPublicValue();
            System.out.println("Public key other party (length): "+ecPublicKeyOtherPartyBytes.length);
            printBytes(ecPublicKeyOtherPartyBytes);
            
            generateSessionKey(c, ecPublicKeyOtherPartyBytes);

            System.out.println("\nEnding client");
	        } catch (UnknownHostException e) {
	            System.err.println("Don't know about host " + hostName);
	            System.exit(1);
	        } catch (IOException e) {
	            System.err.println("Couldn't get I/O for the connection to " +
	                hostName);
	            System.exit(1);
	        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
		
	}

	private static void generateSessionKey(IConnection c, byte[] publicKeyOtherPartyBytes) throws Exception {
		CommandAPDU a;
		ResponseAPDU r;
		
		a = new CommandAPDU(IDENTITY_CARD_CLA, GENERATE_SESSION_KEY, 0x00, 0x00, publicKeyOtherPartyBytes, 0xff);
		r = c.transmit(a);
		if (r.getSW() != 0x9000)
			throw new Exception("Generate SessionKey failed "+r);
		
		
	}

	private static byte[] getECCertificateFromCard(IConnection c) throws Exception {
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
		
		a = new CommandAPDU(IDENTITY_CARD_CLA, CLEAR_OFFSET_INS, 0xf0, 0x00 , 0xff);
		r = c.transmit(a);
		if (r.getSW() != 0x9000)
			throw new Exception("Get certificate failed "+r);
		
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_EC_CERTIFICATE, 0xf0, 0x00 , 0xff);
		r = c.transmit(a);
		if (r.getSW() != 0x9000)
			throw new Exception("Get certificate failed "+r);
		outputStream.write(r.getData());
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_EC_CERTIFICATE, 0xf0, 0x00 , 0xff);
		r = c.transmit(a);
		if (r.getSW() != 0x9000)
			throw new Exception("Get certificate failed "+r);
		outputStream.write(r.getData());
		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_EC_CERTIFICATE, 0x6b, 0x00 , 0xff);
		r = c.transmit(a);
		if (r.getSW() != 0x9000)
			throw new Exception("Get certificate failed "+r);
		outputStream.write(r.getData());
		
		return outputStream.toByteArray();
	}

	private static byte shortToByte(short i) {
		return (byte) ((i >> 8) & 0xff);
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

}

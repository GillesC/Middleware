package Client;

import connection.SecureConnection;
import connection.SmartCardConnection;
import sun.security.ec.ECPublicKeyImpl;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

/**
 * Created by Gilles Callebaut on 24/03/2016.
 *
 */
public class SecurityUtil {



    private static PrivateKey privateKeyCA;
    private static PublicKey publicKeyCA;

    private static boolean loadedCA= false;


    private static void loadCACertificate(String alias, String pwd, String storeName) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        loadedCA = true;
        KeyStore keyStore = KeyStore.getInstance("JKS");
        String fileNameStore1 = new File("certificates\\"+storeName+".jks").getAbsolutePath();
        char[] password = pwd.toCharArray();
        FileInputStream fis = new FileInputStream(fileNameStore1);
        keyStore.load(fis, password);
        fis.close();

        privateKeyCA = (PrivateKey) keyStore.getKey(alias, pwd.toCharArray());
        java.security.cert.Certificate certCA = keyStore.getCertificate(alias);
        publicKeyCA = certCA.getPublicKey();
    }

    public static byte[] getECPublicKeyFromCertificate(byte[] lcpecCertificate, String subjectName) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException, IOException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException, InvalidKeySpecException, NoSuchPaddingException {
        if(!loadedCA) loadCACertificate("LoyaltyCardProvider","LCP","LCP");

        	/* Create cert + get public key */
        X509Certificate certificateOtherParty = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream byteInputStream = new ByteArrayInputStream(lcpecCertificate);
            certificateOtherParty = (X509Certificate) certFactory.generateCertificate(byteInputStream);
        } catch (CertificateException e) {
            e.printStackTrace();
        }

        if(!isCertificateValid(certificateOtherParty, subjectName)){
            System.err.println("Certificate isn't valid!");
            //TODO cleaner way
            System.exit(-1);
        }

        PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();
        ECPublicKeyImpl ecPublicKeyOtherParty = (ECPublicKeyImpl) publicKeyOtherParty;
        byte[] ecPublicKeyOtherPartyBytes = ecPublicKeyOtherParty.getEncodedPublicValue();
        System.out.println("Public key other party (length): " + ecPublicKeyOtherPartyBytes.length);
        Util.printBytes(ecPublicKeyOtherPartyBytes);
        return ecPublicKeyOtherPartyBytes;
    }

    private static boolean isCertificateValid(X509Certificate cert, String subjectName) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, InvalidKeySpecException, IOException, BadPaddingException, IllegalBlockSizeException, ClassNotFoundException {
        if (cert != null) {
            cert.checkValidity(new Date());
            cert.verify(publicKeyCA);
            if (!SecureConnection.checkName(cert, subjectName)) {
                System.err.println("SubjectName doesn't match contacted name...");
            }
        } else {
            System.err.println("ECCertificate is null...");
        }

        return !isCertRevoked(cert);
    }

    private static boolean isCertRevoked(X509Certificate cert) throws IOException, ClassNotFoundException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, CertificateEncodingException {
        System.out.println("Starting unsecure connection with: OCSP server on port: 26262");
        int portNumber= 26262;
        String hostName = "OCSP";
        Socket socket = new Socket(hostName, portNumber);
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        System.out.println("Writing to OCSP server");
        out.writeObject("isCertificateRevoked");
        out.writeObject("Middleware");
        out.writeObject(cert.getEncoded());
        byte isRevoked = SmartCardConnection.decryptWithPrivateKey((byte[]) in.readObject())[0];
        if(isRevoked==0x00){
            System.err.println("Certificate is revoked!");
            return true;
        }
        return false;
    }

    public static PublicKey getPublicRSAKeyFromBytes(byte[] pub) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub));
    }


    public static PrivateKey getPrivateRSAKeyFromBytes(byte[] priv) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(priv));
    }
}

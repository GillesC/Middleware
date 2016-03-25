package Client;

import connection.SecureConnection;
import sun.security.ec.ECPublicKeyImpl;

import java.io.*;
import java.security.*;
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

    public static byte[] getECPublicKeyFromCertificate(byte[] lcpecCertificate, String subjectName) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException, IOException {
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

        checkCertificate(certificateOtherParty, subjectName);

        PublicKey publicKeyOtherParty = certificateOtherParty.getPublicKey();
        ECPublicKeyImpl ecPublicKeyOtherParty = (ECPublicKeyImpl) publicKeyOtherParty;
        byte[] ecPublicKeyOtherPartyBytes = ecPublicKeyOtherParty.getEncodedPublicValue();
        System.out.println("Public key other party (length): " + ecPublicKeyOtherPartyBytes.length);
        Util.printBytes(ecPublicKeyOtherPartyBytes);
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

    public static PublicKey getPublicRSAKeyFromBytes(byte[] pub) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub));
    }


    public static PrivateKey getPrivateRSAKeyFromBytes(byte[] priv) throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(priv));
    }
}

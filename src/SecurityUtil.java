import connection.SecureConnection;
import sun.security.ec.ECPublicKeyImpl;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Created by Gilles Callebaut on 24/03/2016.
 */
public class SecurityUtil {
    private static PrivateKey privateKeyCA;
    private static PublicKey publicKeyCA;

    private static boolean loadedCA= false;


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

    public static byte[] getECPublicKeyFromCertificate(byte[] lcpecCertificate, String subjectName) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnrecoverableKeyException, KeyStoreException, IOException {
        if(!loadedCA) loadCACertificate();

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
}

package connection;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static Client.Client.CLOSE_SECURE_CONNECTION;
import static Client.Client.IDENTITY_CARD_CLA;


/**
 * Created by Gilles Callebaut on 23/03/2016.
 * Implementation of a secure connection based on PKI and ECKeys (in javacard)
 */
public class SecureConnection {
    Map<String, Integer> serviceToPortnumberMap = new HashMap<String, Integer>();
    String hostName = "localhost";
    int portNumber;
    IConnection c;

    public final static String LCP_NAME = "www.LCP.be";
    public final static String MY_JAVACARD_NAME = "www.Javacard.be";

    Socket socket;
    ObjectOutputStream out;
    ObjectInputStream in;

    public SecureConnection(IConnection c) {
        this.c = c;
        mappingPortNumberToService();
    }

    private void mappingPortNumberToService() {
        serviceToPortnumberMap.put("LCP" , 15151);
    }

    public void with(String hostname, String service) throws IOException {
        this.with(hostname, serviceToPortnumberMap.get(service));
    }

    private void with(String hostname, int portNumber) throws IOException {
        this.hostName = hostname;
        this.portNumber = portNumber;

        startSecureConnection();
    }

    private void startSecureConnection() throws IOException {
        System.out.println(hostName+" "+portNumber);
        socket = new Socket(hostName, portNumber);
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        System.out.println("Trying to write to server");
        out.writeObject("SetupSecureConnection");
        System.out.println("Wrote to server");
    }

    public byte[] getECCertificate() throws IOException, ClassNotFoundException {
        /* Getting LCP EC Certificate */
        byte[] LCPECCertificate = (byte[])in.readObject();
        System.out.println("Received certificate");
        for (byte b: LCPECCertificate) {
            System.out.print("0x" + String.format("%02x", b) + " ");
        }
        return  LCPECCertificate;

    }

    public static boolean checkName(X509Certificate cert, String subjectName) throws CertificateEncodingException {
        X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
        RDN cn = x500name.getRDNs(BCStyle.CN)[0];
        String certSubjectName  = IETFUtils.valueToString(cn.getFirst().getValue());
        //System.out.println(certSubjectName+" vs "+subjectName);
        return certSubjectName.equals(subjectName);
    }

    /* Send methods */

    public void send(String requestRegistration) throws IOException {
        out.writeObject(requestRegistration);
    }

    public void send(byte[] bytesToSend) throws IOException {
        out.writeObject(bytesToSend);
    }


    /* receive methods */
    public byte[] receiveBytes() throws IOException, ClassNotFoundException {
        return (byte[])in.readObject();
    }

    public void close(IConnection c) throws Exception{
        CommandAPDU a = new CommandAPDU(IDENTITY_CARD_CLA, CLOSE_SECURE_CONNECTION, 0x00, 0x00, 0xff);
        ResponseAPDU r = c.transmit(a);
        if (r.getSW() != 0x9000)
            throw new Exception("CLOSE_SECURE_CONNECTION failed " + r);
    }
}

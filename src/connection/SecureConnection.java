package connection;

import Client.SecurityUtil;
import Client.Util;
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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import static Client.Client.CLOSE_SECURE_CONNECTION;
import static Client.Client.IDENTITY_CARD_CLA;
import static Client.Client.c;


/**
 * Created by Gilles Callebaut on 23/03/2016.
 * Implementation of a secure connection based on PKI and ECKeys (in javacard)
 */
public class SecureConnection {
    private Map<String, Integer> serviceToPortnumberMap = new HashMap<String, Integer>();
    private String hostName = "localhost";
    private int portNumber;
    private IConnection c;
    private static byte[] cardECCertificate = null;

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
        System.out.println("Loading Portnumbers for services");
        serviceToPortnumberMap.put("LCP" , 15151);
        System.out.println("\t LCP loaded");
        serviceToPortnumberMap.put("Delhaize" , 14000);
        System.out.println("\t Delhaize loaded");
        serviceToPortnumberMap.put("Colruyt" , 14001);
        System.out.println("\t Colruyt loaded");
        serviceToPortnumberMap.put("Carrefour" , 14002);
        System.out.println("\t Carrefour loaded");
        serviceToPortnumberMap.put("Spar" , 14003);
        System.out.println("\t Spar loaded");
        serviceToPortnumberMap.put("Aldi" , 14004);
        System.out.println("\t Aldi loaded");
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
        System.out.println("Starting secure connection with: "+hostName+" port:"+portNumber);
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

    public void send(Object obj) throws IOException {
        out.writeObject(obj);
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

    public static SecureConnection setupSecureConnection(String with, IConnection c) throws Exception {
        long start = System.currentTimeMillis();
        System.out.println("Setting up secure connection at "+start);
        SecureConnection secureConnection = new SecureConnection(c);
        secureConnection.with("localhost", with);

        byte[] ECCertificateOtherParty = secureConnection.getECCertificate();

        /* Sending Card EC certificate */
        System.out.println("\nGetting publicECKey from JavaCard");
        long startECCertFromCard = System.currentTimeMillis();
        if(cardECCertificate==null) cardECCertificate = SmartCardConnection.getECCertificateFromCard();
        else{
            System.out.println("publicECKey is cached, getting it...");
        }
        System.out.println("\t Sending EC certificate..., interval from pull was: "+(System.currentTimeMillis()-startECCertFromCard));
        Util.printBytes(cardECCertificate);

        secureConnection.send(cardECCertificate);
        System.out.println("\t Done sending");

        if(with.equals("LCP")) with = SecureConnection.LCP_NAME;
        long startcheck = System.currentTimeMillis();
        byte[] ecPublicKeyOtherPartyBytes = SecurityUtil.getECPublicKeyFromCertificate(ECCertificateOtherParty, with);
        if(ecPublicKeyOtherPartyBytes==null){
            return null;
        }
        System.out.println("Contatcing OCSP + checking, interval: "+(System.currentTimeMillis()-startcheck));
        System.out.println("\t Sending ecPublicKeyOtherPartyBytes to SC");

        long startGen = System.currentTimeMillis();
        SmartCardConnection.generateSessionKey(ecPublicKeyOtherPartyBytes);
        System.out.println("GENERATING SESSION KEY COMPLETE: "+(System.currentTimeMillis()-startGen));

        System.out.println("\nSecure Connection has been setup, total interval time: "+(System.currentTimeMillis()- start));
        return secureConnection;
    }

    public Object in() throws IOException, ClassNotFoundException {
        return in.readObject();
    }
}

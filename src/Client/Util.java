package Client;

/**
 * Created by Gilles Callebaut on 24/03/2016.
 *
 */
public class Util {

    public static byte shortToByte(int i) {
        return (byte) (((short) i >> 8) & 0xff);
    }

    public static void printBytes(byte[] data) {
        String sb1 = "";
        for (byte b : data) {
            sb1 += "0x" + String.format("%02x", b) + " ";
        }
        System.out.println(sb1);
    }

    public static short readShort(byte[] data, int offset) {
        return (short) (((data[offset] << 8)) | ((data[offset + 1] & 0xff)));
    }
}

import java.math.BigInteger;
import java.util.Base64;

public class Helper {
    
    public static String fromBinaryToHexa(byte[] data){
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static byte[] fromHexaToBinary(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)+ Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    public static String fromBinaryToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] fromBase64ToBinary(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    public static byte[] toFixedLength(BigInteger value, int length) {
        byte[] byteArray = value.toByteArray();

        // Jika ada leading zero karena representasi BigInteger
        if (byteArray.length > 1 && byteArray[0] == 0) {
            byte[] temp = new byte[byteArray.length - 1];
            System.arraycopy(byteArray, 1, temp, 0, temp.length);
            byteArray = temp;
        }

        if (byteArray.length == length) {
            return byteArray;
        } 
        else if (byteArray.length < length) {
            byte[] padded = new byte[length];
            System.arraycopy(byteArray, 0, padded, length - byteArray.length, byteArray.length);
            return padded;
        } 
        else {
            throw new IllegalArgumentException("Value too large to fit in fixed length");
        }
    }
}

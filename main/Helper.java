import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Helper {

    public static PublicKey loadPublicKey(String filePath) throws Exception {
        byte[] keyBytes = fromFiletoBinary(filePath);
        java.security.spec.X509EncodedKeySpec bobPubKeySpec = new java.security.spec.X509EncodedKeySpec(keyBytes);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
        return kf.generatePublic(bobPubKeySpec);
    }

    public static PrivateKey loadPrivateKey(String filePath) throws Exception {
        byte[] keyBytes = fromFiletoBinary(filePath);
        java.security.spec.PKCS8EncodedKeySpec bobPrivKeySpec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
        return kf.generatePrivate(bobPrivKeySpec);
    }
    
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

    public static byte[] fromFiletoBinary(String filePath) throws Exception {
        return java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));
    }

    public static void writeBinarytoFile(byte[] data, String filePath) throws Exception {
        java.nio.file.Files.write(java.nio.file.Paths.get(filePath), data);
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

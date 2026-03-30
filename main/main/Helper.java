package main;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


public class Helper {

    public static PublicKey loadPublicKey(String filePath, String algorithm) throws Exception {
        byte[] keyBytes = fromFiletoBinary(filePath);
        X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance(algorithm);
        return kf.generatePublic(bobPubKeySpec);
    }

    // Method tambahan untuk memuat public key langsung dari byte array (untuk komponen U) di DHIES
    public static PublicKey loadPublicKeyFromBytes(byte[] keyBytes, String algorithm) throws Exception {
        if (keyBytes == null || keyBytes.length == 0) {
            throw new IllegalArgumentException("Key bytes tidak boleh null atau kosong.");
        }

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }

    public static PrivateKey loadPrivateKey(String filePath, String algorithm) throws Exception {
        byte[] keyBytes = fromFiletoBinary(filePath);
        java.security.spec.PKCS8EncodedKeySpec bobPrivKeySpec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance(algorithm);
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

    public static byte[] buildEncryptedPackage(byte[] ephemeralPublicKey, byte[] salt, byte[] ciphertext, byte[] tag) {
        if (ephemeralPublicKey == null || salt == null || ciphertext == null || tag == null) {
            throw new IllegalArgumentException("Komponen paket DHIES tidak boleh null.");
        }

        int totalLength = Integer.BYTES * 4
                + ephemeralPublicKey.length
                + salt.length
                + ciphertext.length
                + tag.length;

        ByteBuffer buffer = ByteBuffer.allocate(totalLength);
        putBytes(buffer, ephemeralPublicKey);
        putBytes(buffer, salt);
        putBytes(buffer, ciphertext);
        putBytes(buffer, tag);

        return buffer.array();
    }

    public static byte[][] parseDHIESPackage(byte[] encryptedPackage) {
        if (encryptedPackage == null || encryptedPackage.length == 0) {
            throw new IllegalArgumentException("Paket DHIES tidak boleh null atau kosong.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(encryptedPackage);

        byte[] ephemeralPublicKey = getBytes(buffer, "ephemeral public key");
        byte[] salt = getBytes(buffer, "salt");
        byte[] ciphertext = getBytes(buffer, "ciphertext");
        byte[] tag = getBytes(buffer, "tag");

        if (buffer.hasRemaining()) {
            throw new IllegalArgumentException("Format paket DHIES tidak valid: ada data berlebih.");
        }

        return new byte[][] { ephemeralPublicKey, salt, ciphertext, tag };
    }

    private static void putBytes(ByteBuffer buffer, byte[] data) {
        buffer.putInt(data.length);
        buffer.put(data);
    }

    private static byte[] getBytes(ByteBuffer buffer, String fieldName) {
        if (buffer.remaining() < Integer.BYTES) {
            throw new IllegalArgumentException("Format paket DHIES tidak valid saat membaca panjang " + fieldName + ".");
        }

        int length = buffer.getInt();
        if (length < 0 || buffer.remaining() < length) {
            throw new IllegalArgumentException("Format paket DHIES tidak valid pada field " + fieldName + ".");
        }

        byte[] result = new byte[length];
        buffer.get(result);
        return result;
    }


    // public static byte[] buildEncryptedPackage(byte[] ephemeralPublicKey, byte[] salt, byte[] ciphertext, byte[] tag)throws Exception {

    //     if (ephemeralPublicKey == null || salt == null || ciphertext == null || tag == null) {
    //         throw new IllegalArgumentException("Komponen paket tidak boleh null.");
    //     }

    //     ByteArrayOutputStream baos = new ByteArrayOutputStream();
    //     DataOutputStream dos = new DataOutputStream(baos);

    //     dos.writeInt(ephemeralPublicKey.length);
    //     dos.write(ephemeralPublicKey);

    //     dos.writeInt(salt.length);
    //     dos.write(salt);

    //     dos.writeInt(ciphertext.length);
    //     dos.write(ciphertext);

    //     dos.writeInt(tag.length);
    //     dos.write(tag);

    //     dos.flush();
    //     return baos.toByteArray();
    // }

    // public static byte[][] parseDHIESPackage(byte[] packageBytes) throws Exception {
    //     if (packageBytes == null || packageBytes.length == 0) {
    //         throw new IllegalArgumentException("Paket DHIES tidak boleh null atau kosong.");
    //     }

    //     ByteArrayInputStream bais = new ByteArrayInputStream(packageBytes);
    //     DataInputStream dis = new DataInputStream(bais);

    //     int lenU = dis.readInt();
    //     byte[] ephemeralPublicKey = new byte[lenU];
    //     dis.readFully(ephemeralPublicKey);

    //     int lenSalt = dis.readInt();
    //     byte[] salt = new byte[lenSalt];
    //     dis.readFully(salt);

    //     int lenCiphertext = dis.readInt();
    //     byte[] ciphertext = new byte[lenCiphertext];
    //     dis.readFully(ciphertext);

    //     int lenTag = dis.readInt();
    //     byte[] tag = new byte[lenTag];
    //     dis.readFully(tag);

    //     return new byte[][]{ephemeralPublicKey, salt, ciphertext, tag};
    // }

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

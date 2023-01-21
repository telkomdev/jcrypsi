package com.wuriyanto.jcrypsi;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AES {

    private AES() {

    }
    
    private static final Integer AESKey128 = 16;
    private static final Integer AESKey192 = 24;
    private static final Integer AESKey256 = 32;

    private static enum AESMode {
        CBC, GCM
    }

    private static final Integer AUTH_TAG_LENGTH = 16;

    private static final Integer IV_SIZE_16 = 16;
    private static final Integer IV_SIZE_12 = 12;

    private static Key loadKey(byte[] key, Integer keySize) throws Exception {
        if (key == null) {
            throw new Exception("key cannot be null");
        }

        if (!Commons.arrayContains(new Integer[]{AES.AESKey128, AES.AESKey192, AES.AESKey256}, key.length)) {
            throw new Exception("invalid key size");
        }

        switch(keySize) {
            case 16:
                if (key.length != AES.AESKey128) {
                    throw new Exception("aes 128 must have 16 bytes key size");
                }
                break;
            
            case 24:
                if (key.length != AES.AESKey192) {
                    throw new Exception("aes 192 must have 24 bytes key size");
                }
                break;
            
            case 32:
                if (key.length != AES.AESKey256) {
                    throw new Exception("aes 256 must have 32 bytes key size");
                }
                break;
        }

        return new SecretKeySpec(key, Commons.AES);
    }

    private static Cipher initAes(AESMode aesMode, Integer mode, 
        byte[] iv, Integer keySize, byte[] key) throws Exception {
        Key secretKey = loadKey(key, keySize);
        Cipher cipher = null;
        switch(aesMode) {
            case CBC:
                cipher = Cipher.getInstance(Commons.AES_CBC_PKCS5_PADDING);

                IvParameterSpec ivParameterSpec = new IvParameterSpec(iv, 0, iv.length);
                cipher.init(mode, secretKey, ivParameterSpec);
                break;

            case GCM:
                cipher = Cipher.getInstance(Commons.AES_GCM_NO_PADDING);

                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(AUTH_TAG_LENGTH*8, iv, 0, iv.length);
                cipher.init(mode, secretKey, gcmParameterSpec);
                break;
        }

        return cipher;
    }

    private static byte[] encrypt(AESMode aesMode, 
        Integer keySize, byte[] key, byte[] data) throws Exception {
        if (data == null) {
            throw new Exception("data cannot be null");
        }

        byte[] iv = null;
        switch(aesMode) {
            case CBC:
                iv = Commons.randomBytes(IV_SIZE_16);
                break;

            case GCM:
                iv = Commons.randomBytes(IV_SIZE_12);
                break;
        }
    
        Cipher cipher = initAes(aesMode, Cipher.ENCRYPT_MODE, iv, keySize, key);
        byte[] cipherData = cipher.doFinal(data);
        byte[] allData = ByteBuffer.allocate(iv.length+cipherData.length)
            .put(iv).put(cipherData).array();
        return Commons.hexEncode(allData).getBytes();
    }

    private static void encrypt(AESMode aesMode, Integer keySize, byte[] key, 
        InputStream inputDataStream, OutputStream encryptedDataStream) throws Exception {
        byte[] bytesData = Commons.inputStreamToByteArray(inputDataStream);
        byte[] encryptedDataBytes = encrypt(aesMode, keySize, key, bytesData);
        encryptedDataStream.write(encryptedDataBytes, 0, encryptedDataBytes.length);
    }

    private static byte[] decrypt(AESMode aesMode, 
        Integer keySize, byte[] key, byte[] encryptedData) throws Exception {
        if (encryptedData == null) {
            throw new Exception("encryptedData cannot be null");
        }

        int ivSize = 0;
        switch(aesMode) {
            case CBC:
                ivSize = IV_SIZE_16;
                break;

            case GCM:
                ivSize = IV_SIZE_12;
                break;
        }

        byte[] encryptedDataUnhex = Commons.hexDecode(new String(encryptedData));

        ByteBuffer encryptedDataBuffer = ByteBuffer.wrap(encryptedDataUnhex);

        byte[] iv = new byte[ivSize];
        byte[] cipherData = new byte[encryptedDataUnhex.length-ivSize];
        encryptedDataBuffer.get(iv, 0, iv.length);
        encryptedDataBuffer.get(cipherData, 0, cipherData.length);

        Cipher cipher = initAes(aesMode, Cipher.DECRYPT_MODE, iv, keySize, key);

        return cipher.doFinal(cipherData);
    }

    private static void decrypt(AESMode aesMode, Integer keySize, byte[] key, 
        InputStream encryptedDataStream, OutputStream plainDataStream) throws Exception {
        byte[] bytesData = Commons.inputStreamToByteArray(encryptedDataStream);
        byte[] decryptedDataBytes = decrypt(aesMode, keySize, key, bytesData);
        plainDataStream.write(decryptedDataBytes, 0, decryptedDataBytes.length);
    }

    // CBC Encrypt
    public static byte[] encryptWithAES128CBC(byte[] data, byte[] key) throws Exception {
        return encrypt(AESMode.CBC, AESKey128, key, data);
    }

    public static void encryptWithAES128CBC( InputStream inputDataStream, 
        OutputStream encryptedDataStream, byte[] key) throws Exception {
        encrypt(AESMode.CBC, AESKey128, key, inputDataStream, encryptedDataStream);
    }

    public static byte[] encryptWithAES192CBC(byte[] data, byte[] key) throws Exception {
        return encrypt(AESMode.CBC, AESKey192, key, data);
    }

    public static void encryptWithAES192CBC( InputStream inputDataStream, 
        OutputStream encryptedDataStream, byte[] key) throws Exception {
        encrypt(AESMode.CBC, AESKey192, key, inputDataStream, encryptedDataStream);
    }

    public static byte[] encryptWithAES256CBC(byte[] data, byte[] key) throws Exception {
        return encrypt(AESMode.CBC, AESKey256, key, data);
    }

    public static void encryptWithAES256CBC( InputStream inputDataStream, 
        OutputStream encryptedDataStream, byte[] key) throws Exception {
        encrypt(AESMode.CBC, AESKey256, key, inputDataStream, encryptedDataStream);
    }

    // CBC Decrypt
    public static byte[] decryptWithAES128CBC(byte[] encryptedData, byte[] key) throws Exception {
        return decrypt(AESMode.CBC, AESKey128, key, encryptedData);
    }

    public static void decryptWithAES128CBC(InputStream encryptedDataStream, 
        OutputStream plainDataStream, byte[] key) throws Exception {
        decrypt(AESMode.CBC, AESKey128, key, encryptedDataStream, plainDataStream);
    }

    public static byte[] decryptWithAES192CBC(byte[] encryptedData, byte[] key) throws Exception {
        return decrypt(AESMode.CBC, AESKey192, key, encryptedData);
    }

    public static void decryptWithAES192CBC(InputStream encryptedDataStream, 
        OutputStream plainDataStream, byte[] key) throws Exception {
        decrypt(AESMode.CBC, AESKey192, key, encryptedDataStream, plainDataStream);
    }

    public static byte[] decryptWithAES256CBC(byte[] encryptedData, byte[] key) throws Exception {
        return decrypt(AESMode.CBC, AESKey256, key, encryptedData);
    }

    public static void decryptWithAES256CBC(InputStream encryptedDataStream, 
        OutputStream plainDataStream, byte[] key) throws Exception {
        decrypt(AESMode.CBC, AESKey256, key, encryptedDataStream, plainDataStream);
    }

    // GCM Encrypt
    public static byte[] encryptWithAES128GCM(byte[] data, byte[] key) throws Exception {
        return encrypt(AESMode.GCM, AESKey128, key, data);
    }

    public static void encryptWithAES128GCM( InputStream inputDataStream, 
        OutputStream encryptedDataStream, byte[] key) throws Exception {
        encrypt(AESMode.GCM, AESKey128, key, inputDataStream, encryptedDataStream);
    }

    public static byte[] encryptWithAES192GCM(byte[] data, byte[] key) throws Exception {
        return encrypt(AESMode.GCM, AESKey192, key, data);
    }

    public static void encryptWithAES192GCM( InputStream inputDataStream, 
        OutputStream encryptedDataStream, byte[] key) throws Exception {
        encrypt(AESMode.GCM, AESKey192, key, inputDataStream, encryptedDataStream);
    }

    public static byte[] encryptWithAES256GCM(byte[] data, byte[] key) throws Exception {
        return encrypt(AESMode.GCM, AESKey256, key, data);
    }

    public static void encryptWithAES256GCM( InputStream inputDataStream, 
        OutputStream encryptedDataStream, byte[] key) throws Exception {
        encrypt(AESMode.GCM, AESKey256, key, inputDataStream, encryptedDataStream);
    }

    // GCM Decrypt
    public static byte[] decryptWithAES128GCM(byte[] encryptedData, byte[] key) throws Exception {
        return decrypt(AESMode.GCM, AESKey128, key, encryptedData);
    }

    public static void decryptWithAES128GCM(InputStream encryptedDataStream, 
        OutputStream plainDataStream, byte[] key) throws Exception {
        decrypt(AESMode.GCM, AESKey128, key, encryptedDataStream, plainDataStream);
    }

    public static byte[] decryptWithAES192GCM(byte[] encryptedData, byte[] key) throws Exception {
        return decrypt(AESMode.GCM, AESKey192, key, encryptedData);
    }

    public static void decryptWithAES192GCM(InputStream encryptedDataStream, 
        OutputStream plainDataStream, byte[] key) throws Exception {
        decrypt(AESMode.GCM, AESKey192, key, encryptedDataStream, plainDataStream);
    }

    public static byte[] decryptWithAES256GCM(byte[] encryptedData, byte[] key) throws Exception {
        return decrypt(AESMode.GCM, AESKey256, key, encryptedData);
    }

    public static void decryptWithAES256GCM(InputStream encryptedDataStream, 
        OutputStream plainDataStream, byte[] key) throws Exception {
        decrypt(AESMode.GCM, AESKey256, key, encryptedDataStream, plainDataStream);
    }
}

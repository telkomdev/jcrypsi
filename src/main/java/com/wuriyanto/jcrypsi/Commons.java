package com.wuriyanto.jcrypsi;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;

 public final class Commons {
    
    private Commons() {
    }

    // https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html

    static final String AES = "AES";
    static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    static final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";
    static final String RSA = "RSA";

    // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PSSParameterSpec.html
    static final String RSASSA_PSS = "RSASSA-PSS";
    static final String RSA_OAEP = "RSA/ECB/OAEPWith%sAndMGF1Padding";
    static final String RAW_BYTES = "RawBytes";

    static final String HMAC_MD5_MAC = "HmacMD5";
    static final String HMAC_SHA1_MAC = "HmacSHA1";
    static final String HMAC_SHA256_MAC = "HmacSHA256";
    static final String HMAC_SHA384_MAC = "HmacSHA384";
    static final String HMAC_SHA512_MAC = "HmacSHA512";

    static final String MD5_DIGEST = "MD5";
    static final String SHA1_DIGEST = "SHA-1";
    static final String SHA256_DIGEST = "SHA-256";
    static final String SHA384_DIGEST = "SHA-384";
    static final String SHA512_DIGEST = "SHA-512";

    static final String MD5_RSA_SIGN = "MD5withRSA";
    static final String SHA1_RSA_SIGN = "SHA1withRSA";
    static final String SHA256_RSA_SIGN = "SHA256withRSA";
    static final String SHA384_RSA_SIGN = "SHA384withRSA";
    static final String SHA512_RSA_SIGN = "SHA512withRSA";

    static final Integer SYMMETRIC_KEY_SIZE = 256;
    static final Integer KEY_SIZE = 32;

    static SecretKeySpec from(byte[] key, String alg) throws Exception {
        if (key.length < KEY_SIZE)
            throw new Exception("key cannot less than " + KEY_SIZE);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, alg);
        return secretKeySpec;
    }

    static byte[] inputStreamToByteArray(InputStream data) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int nRead;
        byte[] buffer = new byte[1024];

        while((nRead = data.read(buffer)) != -1)
            out.write(buffer, 0, nRead);
        
        out.flush();
        return out.toByteArray();
    }

    static <T> boolean arrayContains(T[] arrays, T v) {
        return Arrays.asList(arrays).contains(v);
    }

    public static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        return bytes;
    }

    public static String hexEncode(byte[] bytes) {
        return new String(Hex.encodeHex(bytes));
    }

    public static byte[] hexDecode(String hexString) throws DecoderException {
        return Hex.decodeHex(hexString);
    }
}

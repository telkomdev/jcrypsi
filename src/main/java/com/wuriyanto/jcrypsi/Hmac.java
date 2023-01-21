package com.wuriyanto.jcrypsi;

import java.io.InputStream;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Mac;

public final class Hmac {

    private Hmac() {

    }

    public static String md5(byte[] key, byte[]... data) throws Exception {
        Mac mac = init(key, Commons.HMAC_MD5_MAC);
        return doFinal(mac, data);
    }

    public static String md5(byte[] key, InputStream data) throws Exception {
        Mac mac = init(key, Commons.HMAC_MD5_MAC);
        return doFinal(mac, data);
    }

    public static String sha1(byte[] key, byte[]... data) throws Exception {
        Mac mac = init(key, Commons.HMAC_SHA1_MAC);
        return doFinal(mac, data);
    }

    public static String sha1(byte[] key, InputStream data) throws Exception {
        Mac mac = init(key, Commons.HMAC_SHA1_MAC);
        return doFinal(mac, data);
    }

    public static String sha256(byte[] key, byte[]... data) throws Exception {
        Mac mac = init(key, Commons.HMAC_SHA256_MAC);
        return doFinal(mac, data);
    }

    public static String sha256(byte[] key, InputStream data) throws Exception {
        Mac mac = init(key, Commons.HMAC_SHA256_MAC);
        return doFinal(mac, data);
    }

    public static String sha384(byte[] key, byte[]... data) throws Exception {
        Mac mac = init(key, Commons.HMAC_SHA384_MAC);
        return doFinal(mac, data);
    }

    public static String sha384(byte[] key, InputStream data) throws Exception {
        Mac mac = init(key, Commons.HMAC_SHA384_MAC);
        return doFinal(mac, data);
    }

    public static String sha512(byte[] key, byte[]... data) throws Exception {
        Mac mac = init(key, Commons.HMAC_SHA512_MAC);
        return doFinal(mac, data);
    }

    public static String sha512(byte[] key, InputStream data) throws Exception {
        Mac mac = init(key, Commons.HMAC_SHA512_MAC);
        return doFinal(mac, data);
    }

    public static boolean equals(byte[] m1, byte[] m2) {
        return Arrays.equals(m1, m2);
    }

    private static Mac init(byte[] key, String alg) throws Exception{
        Mac mac = Mac.getInstance(alg);
        Key secretKey = Commons.from(key, alg);
        mac.init(secretKey);
        return mac;
    }

    private static String doFinal(Mac mac, byte[]... datas) {
        for (byte[] data : datas) {
            mac.update(data);
        }
        return Commons.hexEncode(mac.doFinal());
    }

    private static String doFinal(Mac mac, InputStream data) throws Exception {
        byte[] bytesData = Commons.inputStreamToByteArray(data);
        return doFinal(mac, bytesData);
    }
    
}

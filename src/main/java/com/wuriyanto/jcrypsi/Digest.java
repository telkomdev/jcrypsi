package com.wuriyanto.jcrypsi;

import java.io.InputStream;
import java.security.MessageDigest;

public final class Digest {

    private Digest() {

    }

    public static String md5(byte[]... data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.MD5_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    public static String md5(InputStream data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.MD5_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    public static String sha1(byte[]... data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.SHA1_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    public static String sha1(InputStream data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.SHA1_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    public static String sha256(byte[]... data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.SHA256_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    public static String sha256(InputStream data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.SHA256_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    public static String sha384(byte[]... data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.SHA384_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    public static String sha384(InputStream data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.SHA384_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    public static String sha512(byte[]... data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.SHA512_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    public static String sha512(InputStream data) throws Exception {
        MessageDigest messageDigest = MessageDigest.getInstance(Commons.SHA512_DIGEST);
        return Commons.hexEncode(digest(messageDigest, data));
    }

    private static byte[] digest(MessageDigest messageDigest, byte[]... datas) {
        for (byte[] data : datas) {
            messageDigest.update(data);
        }
        
        return messageDigest.digest();
    }

    private static byte[] digest(MessageDigest messageDigest, InputStream data) throws Exception {
        byte[] bytesData = Commons.inputStreamToByteArray(data);
        return digest(messageDigest, bytesData);
    }
}

package com.wuriyanto.jcrypsi;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Map;

public final class RSASignature {

    private RSASignature() {

    }

    private static Integer getDigestSaltLen(String digest) {
        Map<String, Integer> saltLen = new HashMap<String, Integer>();
        saltLen.put(Commons.SHA1_RSA_SIGN, 20);
        saltLen.put(Commons.SHA256_RSA_SIGN, 32);
        saltLen.put(Commons.SHA384_RSA_SIGN, 48);
        saltLen.put(Commons.SHA512_RSA_SIGN, 64);
        return saltLen.get(digest);
    }

    private static byte[] signWithPss(PrivateKey key, String digest, 
        String digestSign, MGF1ParameterSpec mgf1ParameterSpec, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(Commons.RSASSA_PSS);

        SecureRandom secureRandom = new SecureRandom();

        PSSParameterSpec pssParameterSpec = new PSSParameterSpec(digest, "MGF1", mgf1ParameterSpec, 
            getDigestSaltLen(digestSign), PSSParameterSpec.TRAILER_FIELD_BC);
        signature.setParameter(pssParameterSpec);

        signature.initSign(key, secureRandom);

        signature.update(data);
        return signature.sign();
    }

    private static byte[] signWithPss(PrivateKey key, String digest, 
        String digestSign, MGF1ParameterSpec mgf1ParameterSpec, InputStream data) throws Exception {
        byte[] bytesData = Commons.inputStreamToByteArray(data);
        return signWithPss(key, digest, digestSign, mgf1ParameterSpec, bytesData);
    }

    private static boolean verifySignatureWithPss(PublicKey key, String digest, 
        String digestSign, MGF1ParameterSpec mgf1ParameterSpec, 
        byte[] signatureData, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(Commons.RSASSA_PSS);

        PSSParameterSpec pssParameterSpec = new PSSParameterSpec(digest, "MGF1", mgf1ParameterSpec, 
            getDigestSaltLen(digestSign), PSSParameterSpec.TRAILER_FIELD_BC);
        signature.setParameter(pssParameterSpec);

        signature.initVerify(key);

        signature.update(data);
        return signature.verify(signatureData, 0, signatureData.length);
    }

    private static boolean verifySignatureWithPss(PublicKey key, String digest, 
        String digestSign, MGF1ParameterSpec mgf1ParameterSpec, 
        byte[] signatureData, InputStream data) throws Exception {
        byte[] bytesData = Commons.inputStreamToByteArray(data);
        return verifySignatureWithPss(key, digest, digestSign, mgf1ParameterSpec, signatureData, bytesData);
    }

    public static byte[] signWithPssSha1(PrivateKey key, byte[] data) throws Exception {
        return signWithPss(key, Commons.SHA1_DIGEST, Commons.SHA1_RSA_SIGN, MGF1ParameterSpec.SHA1, data);
    }

    public static byte[] signWithPssSha1(PrivateKey key, InputStream data) throws Exception {
        return signWithPss(key, Commons.SHA1_DIGEST, Commons.SHA1_RSA_SIGN, MGF1ParameterSpec.SHA1, data);
    }

    public static byte[] signWithPssSha256(PrivateKey key, byte[] data) throws Exception {
        return signWithPss(key, Commons.SHA256_DIGEST, Commons.SHA256_RSA_SIGN, MGF1ParameterSpec.SHA256, data);
    }

    public static byte[] signWithPssSha256(PrivateKey key, InputStream data) throws Exception {
        return signWithPss(key, Commons.SHA256_DIGEST, Commons.SHA256_RSA_SIGN, MGF1ParameterSpec.SHA256, data);
    }

    public static byte[] signWithPssSha384(PrivateKey key, byte[] data) throws Exception {
        return signWithPss(key, Commons.SHA384_DIGEST, Commons.SHA384_RSA_SIGN, MGF1ParameterSpec.SHA384, data);
    }

    public static byte[] signWithPssSha384(PrivateKey key, InputStream data) throws Exception {
        return signWithPss(key, Commons.SHA384_DIGEST, Commons.SHA384_RSA_SIGN, MGF1ParameterSpec.SHA384, data);
    }

    public static byte[] signWithPssSha512(PrivateKey key, byte[] data) throws Exception {
        return signWithPss(key, Commons.SHA512_DIGEST, Commons.SHA512_RSA_SIGN, MGF1ParameterSpec.SHA512, data);
    }

    public static byte[] signWithPssSha512(PrivateKey key, InputStream data) throws Exception {
        return signWithPss(key, Commons.SHA512_DIGEST, Commons.SHA512_RSA_SIGN, MGF1ParameterSpec.SHA512, data);
    }

    public static boolean verifySignatureWithPssSha1(PublicKey key, 
        byte[] signature, byte[] data) throws Exception {
        return verifySignatureWithPss(key, Commons.SHA1_DIGEST, 
            Commons.SHA1_RSA_SIGN, MGF1ParameterSpec.SHA1, signature, data);
    }

    public static boolean verifySignatureWithPssSha1(PublicKey key, 
        byte[] signature, InputStream data) throws Exception {
        return verifySignatureWithPss(key, Commons.SHA1_DIGEST, 
            Commons.SHA1_RSA_SIGN, MGF1ParameterSpec.SHA1, signature, data);
    }

    public static boolean verifySignatureWithPssSha256(PublicKey key, 
        byte[] signature, byte[] data) throws Exception {
        return verifySignatureWithPss(key, Commons.SHA256_DIGEST, 
            Commons.SHA256_RSA_SIGN, MGF1ParameterSpec.SHA256, signature, data);
    }

    public static boolean verifySignatureWithPssSha256(PublicKey key, 
        byte[] signature, InputStream data) throws Exception {
        return verifySignatureWithPss(key, Commons.SHA256_DIGEST, 
            Commons.SHA256_RSA_SIGN, MGF1ParameterSpec.SHA256, signature, data);
    }

    public static boolean verifySignatureWithPssSha384(PublicKey key, 
        byte[] signature, byte[] data) throws Exception {
        return verifySignatureWithPss(key, Commons.SHA384_DIGEST, 
            Commons.SHA384_RSA_SIGN, MGF1ParameterSpec.SHA384, signature, data);
    }

    public static boolean verifySignatureWithPssSha384(PublicKey key, 
        byte[] signature, InputStream data) throws Exception {
        return verifySignatureWithPss(key, Commons.SHA384_DIGEST, 
            Commons.SHA384_RSA_SIGN, MGF1ParameterSpec.SHA384, signature, data);
    }

    public static boolean verifySignatureWithPssSha512(PublicKey key, 
        byte[] signature, byte[] data) throws Exception {
        return verifySignatureWithPss(key, Commons.SHA512_DIGEST, 
            Commons.SHA512_RSA_SIGN, MGF1ParameterSpec.SHA512, signature, data);
    }

    public static boolean verifySignatureWithPssSha512(PublicKey key, 
        byte[] signature, InputStream data) throws Exception {
        return verifySignatureWithPss(key, Commons.SHA512_DIGEST, 
            Commons.SHA512_RSA_SIGN, MGF1ParameterSpec.SHA512, signature, data);
    }
}
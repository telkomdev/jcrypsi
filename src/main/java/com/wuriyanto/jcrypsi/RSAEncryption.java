package com.wuriyanto.jcrypsi;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class RSAEncryption {
    
    private RSAEncryption() {

    }

    private static byte[] init(int mode, Key key, String digest, 
        MGF1ParameterSpec mgf1ParameterSpec, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(String.format(Commons.RSA_OAEP, digest));
        cipher.init(mode, key, new OAEPParameterSpec(digest, "MGF1", mgf1ParameterSpec, PSource.PSpecified.DEFAULT));
        return cipher.doFinal(data);
    }

    private static byte[] encryptWithOAEP(PublicKey publicKey, String digest, 
        MGF1ParameterSpec mgf1ParameterSpec, byte[] data) throws Exception {
        return init(Cipher.ENCRYPT_MODE, publicKey, digest, mgf1ParameterSpec, data);
    }

    private static byte[] decryptWithOAEP(PrivateKey privateKey, String digest, 
        MGF1ParameterSpec mgf1ParameterSpec, byte[] data) throws Exception {
        return init(Cipher.DECRYPT_MODE, privateKey, digest, mgf1ParameterSpec, data);
    }

    // encrypt
    public static byte[] encryptWithOAEPSha1(PublicKey publicKey, byte[] data) throws Exception {
        return encryptWithOAEP(publicKey, Commons.SHA1_DIGEST, MGF1ParameterSpec.SHA1, data);
    }

    public static byte[] encryptWithOAEPSha256(PublicKey publicKey, byte[] data) throws Exception {
        return encryptWithOAEP(publicKey, Commons.SHA256_DIGEST, MGF1ParameterSpec.SHA256, data);
    }

    public static byte[] encryptWithOAEPSha384(PublicKey publicKey, byte[] data) throws Exception {
        return encryptWithOAEP(publicKey, Commons.SHA384_DIGEST, MGF1ParameterSpec.SHA384, data);
    }

    public static byte[] encryptWithOAEPSha512(PublicKey publicKey, byte[] data) throws Exception {
        return encryptWithOAEP(publicKey, Commons.SHA512_DIGEST, MGF1ParameterSpec.SHA512, data);
    }

    // decrypt
    public static byte[] decryptWithOAEPSha1(PrivateKey privateKey, byte[] data) throws Exception {
        return decryptWithOAEP(privateKey, Commons.SHA1_DIGEST, MGF1ParameterSpec.SHA1, data);
    }

    public static byte[] decryptWithOAEPSha256(PrivateKey privateKey, byte[] data) throws Exception {
        return decryptWithOAEP(privateKey, Commons.SHA256_DIGEST, MGF1ParameterSpec.SHA256, data);
    }

    public static byte[] decryptWithOAEPSha384(PrivateKey privateKey, byte[] data) throws Exception {
        return decryptWithOAEP(privateKey, Commons.SHA384_DIGEST, MGF1ParameterSpec.SHA384, data);
    }

    public static byte[] decryptWithOAEPSha512(PrivateKey privateKey, byte[] data) throws Exception {
        return decryptWithOAEP(privateKey, Commons.SHA512_DIGEST, MGF1ParameterSpec.SHA512, data);
    }
}

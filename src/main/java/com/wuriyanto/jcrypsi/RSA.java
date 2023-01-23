package com.wuriyanto.jcrypsi;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class RSA {

    public static final Integer KEY_SIZE_1KB = 1 << 10; // 1024
    public static final Integer KEY_SIZE_2KB = 1 << 11; // 2048
    public static final Integer KEY_SIZE_4KB = 1 << 12; // 4096

    private int keySize;
    private KeyPair keyPair;

    public RSA(int keySize) {
        if (keySize != KEY_SIZE_1KB || keySize != KEY_SIZE_2KB)
            this.keySize = KEY_SIZE_2KB;
        else
            this.keySize = keySize;
    }

    public void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(Commons.RSA);
        keyPairGenerator.initialize(this.keySize);
        this.keyPair = keyPairGenerator.generateKeyPair();
    }

    // required private key with PKCS8 format
    // convert your RSA Private Key to PKCS8 format first
    // $ openssl pkcs8 -topk8 -inform PEM -in private_key.pem -out private_key_pkcs8.pem -nocrypt
    public static PrivateKey loadPrivateKey(InputStream inputStream) throws Exception {
        byte[] keyBytes = Commons.inputStreamToByteArray(inputStream);

        // remove Header
        String keyWithHeader = new String(keyBytes);
        keyWithHeader = removePKCS8PrivateKeyHeader(keyWithHeader);

        byte[] decoded = Base64.getDecoder().decode(keyWithHeader);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(Commons.RSA);
        return kf.generatePrivate(spec);

    }

    public static PublicKey loadPublicKey(InputStream inputStream) throws Exception {
        byte[] keyBytes = Commons.inputStreamToByteArray(inputStream);

        // remove Header
        String keyWithHeader = new String(keyBytes);
        keyWithHeader = removePKIXPublicKeyHeader(keyWithHeader);

        byte[] decoded = Base64.getDecoder().decode(keyWithHeader);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory kf = KeyFactory.getInstance(Commons.RSA);
        return kf.generatePublic(spec);
    }

    private static String removePKCS8PrivateKeyHeader(String base64Key) {
        base64Key = base64Key.replace("-----BEGIN PRIVATE KEY-----", "").replace("\n", "");
        base64Key = base64Key.replace("-----END PRIVATE KEY-----", "");
        return base64Key;
    }

    private static String removePKIXPublicKeyHeader(String base64Key) {
        base64Key = base64Key.replace("-----BEGIN PUBLIC KEY-----", "").replace("\n", "");
        base64Key = base64Key.replace("-----END PUBLIC KEY-----", "");
        return base64Key;
    }

    public PrivateKey getPrivateKey() throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");
        return this.keyPair.getPrivate();
    }

    public PublicKey getPublicKey() throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");
        return this.keyPair.getPublic();
    }

    // format will be PKCS8 without header
    public String exportPKCS8PrivateKeyToBase64() throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");
        return Base64.getEncoder().
                encodeToString(this.keyPair.getPrivate().getEncoded());
    }

    // format will be X.509 or PKIX without header
    public String exportPKIXPublicKeyToBase64() throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");
        return Base64.getEncoder().
                encodeToString(this.keyPair.getPublic().getEncoded());
    }

    public String exportPKCS8PrivateKeyToHexStr() throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");
        return Commons.hexEncode(this.keyPair.getPrivate().getEncoded());
    }

    public String exportPKIXPublicKeyToHexStr() throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");
        return Commons.hexEncode(this.keyPair.getPublic().getEncoded());
    }

    public String getPrivateKeyFormat() throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");
        return this.keyPair.getPrivate().getFormat();
    }

    public String getPublicKeyFormat() throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");
        return this.keyPair.getPublic().getFormat();
    }

    // format will be PKCS8 with header
    public void exportPKCS8PrivateKeyToStream(OutputStream outputStream) throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");

        String privateKeyBase64Str = exportPKCS8PrivateKeyToBase64();
        byte[] privateKeyBase64Bytes = privateKeyBase64Str.getBytes();

        outputStream.write("-----BEGIN PRIVATE KEY-----\n".getBytes());
        for (int i = 0; i < privateKeyBase64Bytes.length; i += 64) {
            outputStream.write(privateKeyBase64Bytes, i, Math.min(64, privateKeyBase64Bytes.length-i));
            outputStream.write("\n".getBytes());
        }

        outputStream.write("-----END PRIVATE KEY-----".getBytes());
    }

    // format will be X.509 or PKIX with header
    public void exportPKIXPublicKeyToStream(OutputStream outputStream) throws Exception {
        if (this.keyPair == null)
            throw new Exception("key pair is null, call generateKeyPair first");

        String publicKeyBase64Str = exportPKIXPublicKeyToBase64();
        byte[] publicKeyBase64Bytes = publicKeyBase64Str.getBytes();

        outputStream.write("-----BEGIN PUBLIC KEY-----\n".getBytes());
        for (int i = 0; i < publicKeyBase64Bytes.length; i += 64) {
            outputStream.write(publicKeyBase64Bytes, i, Math.min(64, publicKeyBase64Bytes.length-i));
            outputStream.write("\n".getBytes());
        }

        outputStream.write("-----END PUBLIC KEY-----".getBytes());
    }
    
}

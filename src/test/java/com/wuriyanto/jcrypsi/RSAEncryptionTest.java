package com.wuriyanto.jcrypsi;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RSAEncryptionTest {

    @Test
    public void testEncryptAndDecryptWithOaepSHA1() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();
        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;
        try {
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            String data = "jcrypsi for jvm";

            byte[] encryptedData = RSAEncryption.encryptWithOAEPSha1(publicKey, data.getBytes());

            byte[] decryptedData = RSAEncryption.decryptWithOAEPSha1(privateKey, encryptedData);

            Assertions.assertEquals(data, new String(decryptedData));
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testEncryptAndDecryptWithOaepSHA256() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();
        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;
        try {
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            String data = "jcrypsi for jvm";

            byte[] encryptedData = RSAEncryption.encryptWithOAEPSha256(publicKey, data.getBytes());

            byte[] decryptedData = RSAEncryption.decryptWithOAEPSha256(privateKey, encryptedData);

            Assertions.assertEquals(data, new String(decryptedData));
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testEncryptAndDecryptWithOaepSHA384() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();
        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;
        try {
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            String data = "jcrypsi for jvm";

            byte[] encryptedData = RSAEncryption.encryptWithOAEPSha384(publicKey, data.getBytes());

            byte[] decryptedData = RSAEncryption.decryptWithOAEPSha384(privateKey, encryptedData);

            Assertions.assertEquals(data, new String(decryptedData));
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testEncryptAndDecryptWithOaepSHA512() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();
        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;
        try {
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            String data = "jcrypsi for jvm";

            byte[] encryptedData = RSAEncryption.encryptWithOAEPSha512(publicKey, data.getBytes());

            byte[] decryptedData = RSAEncryption.decryptWithOAEPSha512(privateKey, encryptedData);

            Assertions.assertEquals(data, new String(decryptedData));
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }
}

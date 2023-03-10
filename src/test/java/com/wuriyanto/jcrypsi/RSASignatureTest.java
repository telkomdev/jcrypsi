package com.wuriyanto.jcrypsi;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RSASignatureTest {

    @Test
    public void testSignAndVerifyWithPssSHA1() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();
        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;

        FileInputStream burgerFileStreamSign = null;
        FileInputStream burgerFileStreamVerify = null;
        try {
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            File burgerFileSign = new File(testdataPath+"/burger.png");
            File burgerFileVerify = new File(testdataPath+"/burger.png");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            burgerFileStreamSign = new FileInputStream(burgerFileSign);
            burgerFileStreamVerify = new FileInputStream(burgerFileVerify);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            byte[] signature = RSASignature.signWithPssSha1(privateKey, burgerFileStreamSign);

            boolean validSignature = RSASignature.verifySignatureWithPssSha1(publicKey, signature, burgerFileStreamVerify);

            Assertions.assertTrue(validSignature);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();
                
                if (burgerFileStreamSign != null)
                    burgerFileStreamSign.close();
                
                if (burgerFileStreamVerify != null)
                    burgerFileStreamVerify.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testSignAndVerifyWithPssSHA256() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();
        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;

        FileInputStream burgerFileStreamSign = null;
        FileInputStream burgerFileStreamVerify = null;
        try {
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            File burgerFileSign = new File(testdataPath+"/burger.png");
            File burgerFileVerify = new File(testdataPath+"/burger.png");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            burgerFileStreamSign = new FileInputStream(burgerFileSign);
            burgerFileStreamVerify = new FileInputStream(burgerFileVerify);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            byte[] signature = RSASignature.signWithPssSha256(privateKey, burgerFileStreamSign);

            boolean validSignature = RSASignature.verifySignatureWithPssSha256(publicKey, signature, burgerFileStreamVerify);

            Assertions.assertTrue(validSignature);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();
                
                if (burgerFileStreamSign != null)
                    burgerFileStreamSign.close();
                
                if (burgerFileStreamVerify != null)
                    burgerFileStreamVerify.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testSignAndVerifyWithPssSHA384() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();
        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;

        FileInputStream burgerFileStreamSign = null;
        FileInputStream burgerFileStreamVerify = null;
        try {
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            File burgerFileSign = new File(testdataPath+"/burger.png");
            File burgerFileVerify = new File(testdataPath+"/burger.png");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            burgerFileStreamSign = new FileInputStream(burgerFileSign);
            burgerFileStreamVerify = new FileInputStream(burgerFileVerify);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            byte[] signature = RSASignature.signWithPssSha384(privateKey, burgerFileStreamSign);

            boolean validSignature = RSASignature.verifySignatureWithPssSha384(publicKey, signature, burgerFileStreamVerify);

            Assertions.assertTrue(validSignature);
        } catch(Exception e) {
            System.out.println(e.getMessage());
            Assertions.assertNull(e);
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();
                
                if (burgerFileStreamSign != null)
                    burgerFileStreamSign.close();
                
                if (burgerFileStreamVerify != null)
                    burgerFileStreamVerify.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testSignAndVerifyWithPssSHA512() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();
        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;

        FileInputStream burgerFileStreamSign = null;
        FileInputStream burgerFileStreamVerify = null;
        try {
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            File burgerFileSign = new File(testdataPath+"/burger.png");
            File burgerFileVerify = new File(testdataPath+"/burger.png");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            burgerFileStreamSign = new FileInputStream(burgerFileSign);
            burgerFileStreamVerify = new FileInputStream(burgerFileVerify);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            byte[] signature = RSASignature.signWithPssSha512(privateKey, burgerFileStreamSign);

            boolean validSignature = RSASignature.verifySignatureWithPssSha512(publicKey, signature, burgerFileStreamVerify);

            Assertions.assertTrue(validSignature);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();
                
                if (burgerFileStreamSign != null)
                    burgerFileStreamSign.close();
                
                if (burgerFileStreamVerify != null)
                    burgerFileStreamVerify.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testSignAndVerifyWithPssSHA512ShouldFailWithInvalidSignature() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();
        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;

        FileInputStream burgerFileStreamSign = null;
        FileInputStream burgerFileStreamVerify = null;
        try {
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            File burgerFileSign = new File(testdataPath+"/private.key");
            File burgerFileVerify = new File(testdataPath+"/burger.png");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            burgerFileStreamSign = new FileInputStream(burgerFileSign);
            burgerFileStreamVerify = new FileInputStream(burgerFileVerify);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            byte[] signature = RSASignature.signWithPssSha512(privateKey, burgerFileStreamSign);

            boolean validSignature = RSASignature.verifySignatureWithPssSha512(publicKey, signature, burgerFileStreamVerify);

            Assertions.assertFalse(validSignature);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();
                
                if (burgerFileStreamSign != null)
                    burgerFileStreamSign.close();
                
                if (burgerFileStreamVerify != null)
                    burgerFileStreamVerify.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }
}

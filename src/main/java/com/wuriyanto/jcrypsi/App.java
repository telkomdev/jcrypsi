package com.wuriyanto.jcrypsi;

import java.nio.file.Path;
import java.nio.file.Paths;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Hello world!
 *
 */
public class App {
    public static void main( String[] args ){
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        String key128 = "abc$#128djdyAgbj";
        String key192 = "abc$#128djdyAgbjau&YAnmc";
        String key256 = "abc$#128djdyAgbjau&YAnmcbagryt5x";

        System.out.println( "Hello World!" );
        String key = "abc$#128djdyAgbjau&YAnmcbagryt5x";
        String data = "wuriyanto";

        FileInputStream privateKeyStream = null;
        FileInputStream publicKeyStream = null;

        FileOutputStream privateKeyStreamOut = null;
        FileOutputStream publicKeyStreamOut = null;
        try {
            // String macRes = Hmac.sha512(key.getBytes(), new ByteArrayInputStream(data.getBytes()));
            // System.out.println(macRes);

            // write private key and public key
            RSA rsa = new RSA(RSA.KEY_SIZE_2KB);
            rsa.generateKeyPair();

            System.out.println(rsa.getPrivateKeyFormat());
            System.out.println(rsa.getPublicKeyFormat());

            // privateKeyStreamOut = new FileOutputStream(new File("./private2.key"));
            // publicKeyStreamOut = new FileOutputStream(new File("./public2.key"));

            // rsa.exportPKCS8PrivateKeyToStream(privateKeyStreamOut);
            // rsa.exportPKIXPublicKeyToStream(publicKeyStreamOut);

            System.out.println(rsa.exportPKCS8PrivateKeyToBase64());
            System.out.println(rsa.exportPKIXPublicKeyToBase64());

            RSA.loadPrivateKey(new ByteArrayInputStream(rsa.exportPKCS8PrivateKeyToBase64().getBytes()));
            RSA.loadPublicKey(new ByteArrayInputStream(rsa.exportPKIXPublicKeyToBase64().getBytes()));

            System.out.println("---------------------------------------------------");

            //  ---------------------------------------------------
            
            File privateKeyFile = new File(testdataPath+"/private.key");
            File publicKeyFile = new File(testdataPath+"/public.key");

            privateKeyStream = new FileInputStream(privateKeyFile);
            publicKeyStream = new FileInputStream(publicKeyFile);

            PrivateKey privateKey = RSA.loadPrivateKey(privateKeyStream);
            PublicKey publicKey = RSA.loadPublicKey(publicKeyStream);

            byte[] rsaEncryptedData = RSAEncryption.encryptWithOAEPSha256(publicKey, data.getBytes());
            String rsaEncryptedDataHexStr = Commons.hexEncode(rsaEncryptedData);
            
            System.out.println(rsaEncryptedDataHexStr);
            byte[] rsaDecryptedData = RSAEncryption.decryptWithOAEPSha256(privateKey, Commons.hexDecode("3dce642dfa8f400732d0912c8809a85496ce93736ef112e70ae72a1d67403bd081d5fa1aa67ab2572786898feffe043a7fcc0ebb9bc91b36c7a5814d5d53333e67ac17e4de9a4296d4a98def830e7dbc0e2e70838e451cab92d458d4c5054930022722c144a165fcc8ef1f349c0c35bb67526fd2f281af1de423b270e6e96b7604d892b43998d743186bb67bf084f2cf3dd982008d2e6b8af90302144cb2a2d7d091e7a2b9d6e3319ad9d1b3e7044e863f51f4f0be8d52e8cc0225c40583bd3d55dc50d9283ff238787cf63eec820db9c86af73329f4e2a29883852969abf848c25d38001569a080c3f9569dd3d7f9fe50e9ecb3d520f57a3359d7edf1dc3fce"));
            System.out.println(new String(rsaDecryptedData));

            System.out.println("-------------");

            String data2 = "This is your actual question; all of the above is just a preambule.";
            byte[] signature = RSASignature.signWithPssSha256(privateKey, data2.getBytes());
            String signatureHexStr = Commons.hexEncode(signature);
            System.out.println(signatureHexStr);

            boolean validSignature = RSASignature.verifySignatureWithPssSha256(publicKey, signature, data2.getBytes());
            System.out.println(validSignature);

            System.out.println("------ AES -------");

            byte[] aesEncrypted = AES.encryptWithAES256GCM("Atom was a free and open-source text and source".getBytes(), key256.getBytes());
            System.out.println(new String(aesEncrypted));

            byte[] aesDecrypted = AES.decryptWithAES256GCM(aesEncrypted, key256.getBytes());
            System.out.println(new String(aesDecrypted));

            


        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (privateKeyStream != null)
                    privateKeyStream.close();

                if (publicKeyStream != null)
                    publicKeyStream.close();

                if (privateKeyStreamOut != null)
                    privateKeyStreamOut.close();
                
                if (publicKeyStreamOut != null)
                    publicKeyStreamOut.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }




        // System.out.println("------ AES IO Encrypt -------");

        // FileInputStream fileInputStream = null;
        // FileOutputStream fileOutputStream = null;

        // try {
        //     fileInputStream = new FileInputStream(new File("./burger.png"));
        //     fileOutputStream = new FileOutputStream(new File("./burger.bin"));

        //     AES.encryptWithAES256GCM(fileInputStream, fileOutputStream, key256.getBytes());
        // } catch(Exception e) {
        //     e.printStackTrace();
        // } finally {
        //     try {
        //         if (fileInputStream != null)
        //         fileInputStream.close();

        //         if (fileOutputStream != null)
        //         fileOutputStream.close();
        //     } catch (Exception e) {
        //         e.printStackTrace();
        //     }
        // }



        // System.out.println("------ AES IO Decrypt -------");

        // FileInputStream fileInputStream = null;
        // FileOutputStream fileOutputStream = null;

        // try {
        //     fileInputStream = new FileInputStream(new File("./burger.bin"));
        //     fileOutputStream = new FileOutputStream(new File("./burger_dec.png"));

        //     AES.decryptWithAES256GCM(fileInputStream, fileOutputStream, key256.getBytes());
        // } catch(Exception e) {
        //     e.printStackTrace();
        // } finally {
        //     try {
        //         if (fileInputStream != null)
        //         fileInputStream.close();

        //         if (fileOutputStream != null)
        //         fileOutputStream.close();
        //     } catch (Exception e) {
        //         e.printStackTrace();
        //     }
        // }
    }
}

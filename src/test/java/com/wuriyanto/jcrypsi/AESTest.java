package com.wuriyanto.jcrypsi;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class AESTest {

    private final String KEY_128 = "kJjG$qMCzbzqW6WW";
    private final String KEY_192 = "kJjG$qMCzbzqW6WWge2ZHFD7";
    private final String KEY_256 = "kJjG$qMCzbzqW6WWge2ZHFD777gjERHO";

    @Test
    public void testDummyTestAes() {
        Assertions.assertTrue(true);
    }

    // AES CBC Encrypt and Decrypt Bytes

    @Test
    public void testEncryptBytesDataWithAES128CBCShouldEqualToDecryptedData() throws Exception {
        String expected = "wuriyanto";

        byte[] encryptedData = AES.encryptWithAES128CBC(expected.getBytes(), KEY_128.getBytes());
        byte[] decryptedData = AES.decryptWithAES128CBC(encryptedData, KEY_128.getBytes());

        String actual = new String(decryptedData);
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testEncryptBytesDataWithAES192CBCShouldEqualToDecryptedData() throws Exception {
        String expected = "wuriyanto";

        byte[] encryptedData = AES.encryptWithAES192CBC(expected.getBytes(), KEY_192.getBytes());
        byte[] decryptedData = AES.decryptWithAES192CBC(encryptedData, KEY_192.getBytes());

        String actual = new String(decryptedData);
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testEncryptBytesDataWithAES256CBCShouldEqualToDecryptedData() throws Exception {
        String expected = "wuriyanto";

        byte[] encryptedData = AES.encryptWithAES256CBC(expected.getBytes(), KEY_256.getBytes());
        byte[] decryptedData = AES.decryptWithAES256CBC(encryptedData, KEY_256.getBytes());

        String actual = new String(decryptedData);
        Assertions.assertEquals(expected, actual);
    }

    // AES CBC Encrypt and Decrypt Stream
    @Test
    public void testEncryptStreamDataWithAES128CBCShouldEqualToDecryptedData() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;
        FileInputStream burgerFileInputStreamExpected = null;

        ByteArrayOutputStream burgerOutputStreamEncrypted = null;
        ByteArrayOutputStream burgerOutputStreamDecrypted = null;
        try {

            burgerOutputStreamEncrypted = new ByteArrayOutputStream();
            burgerOutputStreamDecrypted = new ByteArrayOutputStream();

            File burgerFileInput = new File(testdataPath+"/burger.png");
            File burgerFileExpected = new File(testdataPath+"/burger.png");

            burgerFileInputStream = new FileInputStream(burgerFileInput);
            burgerFileInputStreamExpected = new FileInputStream(burgerFileExpected);

            AES.encryptWithAES128CBC(burgerFileInputStream, burgerOutputStreamEncrypted, KEY_128.getBytes());
            AES.decryptWithAES128CBC(new ByteArrayInputStream(burgerOutputStreamEncrypted.toByteArray()), burgerOutputStreamDecrypted, KEY_128.getBytes());

            String expected = Digest.sha256(burgerFileInputStreamExpected);
            String actual = Digest.sha256(new ByteArrayInputStream(burgerOutputStreamDecrypted.toByteArray()));

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();
                
                if (burgerFileInputStreamExpected != null)
                    burgerFileInputStreamExpected.close();
                
                if (burgerOutputStreamEncrypted != null)
                    burgerOutputStreamEncrypted.close();
                
                if (burgerOutputStreamDecrypted != null)
                    burgerOutputStreamDecrypted.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testEncryptStreamDataWithAES192CBCShouldEqualToDecryptedData() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;
        FileInputStream burgerFileInputStreamExpected = null;

        ByteArrayOutputStream burgerOutputStreamEncrypted = null;
        ByteArrayOutputStream burgerOutputStreamDecrypted = null;
        try {

            burgerOutputStreamEncrypted = new ByteArrayOutputStream();
            burgerOutputStreamDecrypted = new ByteArrayOutputStream();

            File burgerFileInput = new File(testdataPath+"/burger.png");
            File burgerFileExpected = new File(testdataPath+"/burger.png");

            burgerFileInputStream = new FileInputStream(burgerFileInput);
            burgerFileInputStreamExpected = new FileInputStream(burgerFileExpected);

            AES.encryptWithAES192CBC(burgerFileInputStream, burgerOutputStreamEncrypted, KEY_192.getBytes());
            AES.decryptWithAES192CBC(new ByteArrayInputStream(burgerOutputStreamEncrypted.toByteArray()), burgerOutputStreamDecrypted, KEY_192.getBytes());

            String expected = Digest.sha256(burgerFileInputStreamExpected);
            String actual = Digest.sha256(new ByteArrayInputStream(burgerOutputStreamDecrypted.toByteArray()));

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();
                
                if (burgerFileInputStreamExpected != null)
                    burgerFileInputStreamExpected.close();
                
                if (burgerOutputStreamEncrypted != null)
                    burgerOutputStreamEncrypted.close();
                
                if (burgerOutputStreamDecrypted != null)
                    burgerOutputStreamDecrypted.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testEncryptStreamDataWithAES256CBCShouldEqualToDecryptedData() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;
        FileInputStream burgerFileInputStreamExpected = null;

        ByteArrayOutputStream burgerOutputStreamEncrypted = null;
        ByteArrayOutputStream burgerOutputStreamDecrypted = null;
        try {

            burgerOutputStreamEncrypted = new ByteArrayOutputStream();
            burgerOutputStreamDecrypted = new ByteArrayOutputStream();

            File burgerFileInput = new File(testdataPath+"/burger.png");
            File burgerFileExpected = new File(testdataPath+"/burger.png");

            burgerFileInputStream = new FileInputStream(burgerFileInput);
            burgerFileInputStreamExpected = new FileInputStream(burgerFileExpected);

            AES.encryptWithAES256CBC(burgerFileInputStream, burgerOutputStreamEncrypted, KEY_256.getBytes());
            AES.decryptWithAES256CBC(new ByteArrayInputStream(burgerOutputStreamEncrypted.toByteArray()), burgerOutputStreamDecrypted, KEY_256.getBytes());

            String expected = Digest.sha256(burgerFileInputStreamExpected);
            String actual = Digest.sha256(new ByteArrayInputStream(burgerOutputStreamDecrypted.toByteArray()));

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();
                
                if (burgerFileInputStreamExpected != null)
                    burgerFileInputStreamExpected.close();
                
                if (burgerOutputStreamEncrypted != null)
                    burgerOutputStreamEncrypted.close();
                
                if (burgerOutputStreamDecrypted != null)
                    burgerOutputStreamDecrypted.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    // AES GCM Encrypt and Decrypt Bytes

    @Test
    public void testEncryptBytesDataWithAES128GCMShouldEqualToDecryptedData() throws Exception {
        String expected = "wuriyanto";

        byte[] encryptedData = AES.encryptWithAES128GCM(expected.getBytes(), KEY_128.getBytes());
        byte[] decryptedData = AES.decryptWithAES128GCM(encryptedData, KEY_128.getBytes());

        String actual = new String(decryptedData);
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testEncryptBytesDataWithAES192GCMShouldEqualToDecryptedData() throws Exception {
        String expected = "wuriyanto";

        byte[] encryptedData = AES.encryptWithAES192GCM(expected.getBytes(), KEY_192.getBytes());
        byte[] decryptedData = AES.decryptWithAES192GCM(encryptedData, KEY_192.getBytes());

        String actual = new String(decryptedData);
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testEncryptBytesDataWithAES256GCMShouldEqualToDecryptedData() throws Exception {
        String expected = "wuriyanto";

        byte[] encryptedData = AES.encryptWithAES256GCM(expected.getBytes(), KEY_256.getBytes());
        byte[] decryptedData = AES.decryptWithAES256GCM(encryptedData, KEY_256.getBytes());

        String actual = new String(decryptedData);
        Assertions.assertEquals(expected, actual);
    }

    // AES CBC Encrypt and Decrypt Stream
    @Test
    public void testEncryptStreamDataWithAES128GCMShouldEqualToDecryptedData() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;
        FileInputStream burgerFileInputStreamExpected = null;

        ByteArrayOutputStream burgerOutputStreamEncrypted = null;
        ByteArrayOutputStream burgerOutputStreamDecrypted = null;
        try {

            burgerOutputStreamEncrypted = new ByteArrayOutputStream();
            burgerOutputStreamDecrypted = new ByteArrayOutputStream();

            File burgerFileInput = new File(testdataPath+"/burger.png");
            File burgerFileExpected = new File(testdataPath+"/burger.png");

            burgerFileInputStream = new FileInputStream(burgerFileInput);
            burgerFileInputStreamExpected = new FileInputStream(burgerFileExpected);

            AES.encryptWithAES128GCM(burgerFileInputStream, burgerOutputStreamEncrypted, KEY_128.getBytes());
            AES.decryptWithAES128GCM(new ByteArrayInputStream(burgerOutputStreamEncrypted.toByteArray()), burgerOutputStreamDecrypted, KEY_128.getBytes());

            String expected = Digest.sha256(burgerFileInputStreamExpected);
            String actual = Digest.sha256(new ByteArrayInputStream(burgerOutputStreamDecrypted.toByteArray()));

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();
                
                if (burgerFileInputStreamExpected != null)
                    burgerFileInputStreamExpected.close();
                
                if (burgerOutputStreamEncrypted != null)
                    burgerOutputStreamEncrypted.close();
                
                if (burgerOutputStreamDecrypted != null)
                    burgerOutputStreamDecrypted.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testEncryptStreamDataWithAESGCMShouldEqualToDecryptedData() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;
        FileInputStream burgerFileInputStreamExpected = null;

        ByteArrayOutputStream burgerOutputStreamEncrypted = null;
        ByteArrayOutputStream burgerOutputStreamDecrypted = null;
        try {

            burgerOutputStreamEncrypted = new ByteArrayOutputStream();
            burgerOutputStreamDecrypted = new ByteArrayOutputStream();

            File burgerFileInput = new File(testdataPath+"/burger.png");
            File burgerFileExpected = new File(testdataPath+"/burger.png");

            burgerFileInputStream = new FileInputStream(burgerFileInput);
            burgerFileInputStreamExpected = new FileInputStream(burgerFileExpected);

            AES.encryptWithAES192GCM(burgerFileInputStream, burgerOutputStreamEncrypted, KEY_192.getBytes());
            AES.decryptWithAES192GCM(new ByteArrayInputStream(burgerOutputStreamEncrypted.toByteArray()), burgerOutputStreamDecrypted, KEY_192.getBytes());
            
            String expected = Digest.sha256(burgerFileInputStreamExpected);
            String actual = Digest.sha256(new ByteArrayInputStream(burgerOutputStreamDecrypted.toByteArray()));

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();
                
                if (burgerFileInputStreamExpected != null)
                    burgerFileInputStreamExpected.close();
                
                if (burgerOutputStreamEncrypted != null)
                    burgerOutputStreamEncrypted.close();
                
                if (burgerOutputStreamDecrypted != null)
                    burgerOutputStreamDecrypted.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testEncryptStreamDataWithAES256GCMShouldEqualToDecryptedData() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;
        FileInputStream burgerFileInputStreamExpected = null;

        ByteArrayOutputStream burgerOutputStreamEncrypted = null;
        ByteArrayOutputStream burgerOutputStreamDecrypted = null;
        try {

            burgerOutputStreamEncrypted = new ByteArrayOutputStream();
            burgerOutputStreamDecrypted = new ByteArrayOutputStream();

            File burgerFileInput = new File(testdataPath+"/burger.png");
            File burgerFileExpected = new File(testdataPath+"/burger.png");

            burgerFileInputStream = new FileInputStream(burgerFileInput);
            burgerFileInputStreamExpected = new FileInputStream(burgerFileExpected);

            AES.encryptWithAES256GCM(burgerFileInputStream, burgerOutputStreamEncrypted, KEY_256.getBytes());
            AES.decryptWithAES256GCM(new ByteArrayInputStream(burgerOutputStreamEncrypted.toByteArray()), burgerOutputStreamDecrypted, KEY_256.getBytes());

            String expected = Digest.sha256(burgerFileInputStreamExpected);
            String actual = Digest.sha256(new ByteArrayInputStream(burgerOutputStreamDecrypted.toByteArray()));

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();
                
                if (burgerFileInputStreamExpected != null)
                    burgerFileInputStreamExpected.close();
                
                if (burgerOutputStreamEncrypted != null)
                    burgerOutputStreamEncrypted.close();
                
                if (burgerOutputStreamDecrypted != null)
                    burgerOutputStreamDecrypted.close();
            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }
}

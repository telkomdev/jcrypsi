package com.wuriyanto.jcrypsi;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class HmacTest {

    @Test
    public void testMD5ShouldEqualToExpected() throws Exception {
        String expected = "d213b2e973c1a5d704255518af6d073c";

        String actual = Hmac.md5("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), "wuriyanto".getBytes());
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testMD5StreamInputShouldEqualToExpected() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;

        try {

            File burgerFileInput = new File(testdataPath+"/burger.png");
            burgerFileInputStream = new FileInputStream(burgerFileInput);

            String expected = "1edf37c5276c8f5ad9e7fe63bd066cdf";
            String actual = Hmac.md5("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), burgerFileInputStream);

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();

            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testMD5ShouldNotEqualToExpectedWhenKeyIsInvalid() throws Exception {
        String expected = "d213b2e973c1a5d704255518af6d073c";

        String actual = Hmac.md5("abc$#128djdyAgbjau&YAnmcbagryt5v".getBytes(), "wuriyanto".getBytes());
        Assertions.assertNotSame(expected, actual);
    }

    @Test
    public void testMD5ShouldThrowExceptionWhenKeyLessThanExpected() {
        try {
            Hmac.md5("abc$#128djdyAgbjau&YAnmcbagryt".getBytes(), "wuriyanto".getBytes());
        } catch(Exception e) {
            Assertions.assertNotNull(e);
        }
    }

    @Test
    public void testSHA1ShouldEqualToExpected() throws Exception {
        String expected = "69fa82ae1f1398e6e570a4780df908adad3998df";

        String actual = Hmac.sha1("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), "wuriyanto".getBytes());
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testSHA1StreamInputShouldEqualToExpected() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;

        try {

            File burgerFileInput = new File(testdataPath+"/burger.png");
            burgerFileInputStream = new FileInputStream(burgerFileInput);

            String expected = "bbc6f9f982c86e4828a8a26167b575785a7515c6";
            String actual = Hmac.sha1("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), burgerFileInputStream);

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();

            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testSHA1ShouldNotEqualToExpectedWhenKeyIsInvalid() throws Exception {
        String expected = "69fa82ae1f1398e6e570a4780df908adad3998df";

        String actual = Hmac.sha1("abc$#128djdyAgbjau&YAnmcbagryt5v".getBytes(), "wuriyanto".getBytes());
        Assertions.assertNotSame(expected, actual);
    }

    @Test
    public void testSHA1ShouldThrowExceptionWhenKeyLessThanExpected() {
        try {
            Hmac.sha1("abc$#128djdyAgbjau&YAnmcbagryt".getBytes(), "wuriyanto".getBytes());
        } catch(Exception e) {
            Assertions.assertNotNull(e);
        }
    }

    @Test
    public void testSHA256ShouldEqualToExpected() throws Exception {
        String expected = "9f46bcc1bdc24ff2d4b6f811c1dd7e053089e515b0525c2b2a7ff25c28eb4240";

        String actual = Hmac.sha256("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), "wuriyanto".getBytes());
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testSHA256StreamInputShouldEqualToExpected() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;

        try {

            File burgerFileInput = new File(testdataPath+"/burger.png");
            burgerFileInputStream = new FileInputStream(burgerFileInput);

            String expected = "aa9a824376b5d0f42322702b463fc552806b548d0d075a70b97cdebb603826ab";
            String actual = Hmac.sha256("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), burgerFileInputStream);

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();

            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testSHA256ShouldNotEqualToExpectedWhenKeyIsInvalid() throws Exception {
        String expected = "9f46bcc1bdc24ff2d4b6f811c1dd7e053089e515b0525c2b2a7ff25c28eb4240";

        String actual = Hmac.sha256("abc$#128djdyAgbjau&YAnmcbagryt5v".getBytes(), "wuriyanto".getBytes());
        Assertions.assertNotSame(expected, actual);
    }

    @Test
    public void testSHA256ShouldThrowExceptionWhenKeyLessThanExpected() {
        try {
            Hmac.sha256("abc$#128djdyAgbjau&YAnmcbagryt".getBytes(), "wuriyanto".getBytes());
        } catch(Exception e) {
            Assertions.assertNotNull(e);
        }
    }

    @Test
    public void testSHA384ShouldEqualToExpected() throws Exception {
        String expected = "69b5b98267f760b5dc39cde790adc89358c9a59d7eac7e76c5a9e7acb9c037d0293810251de16afdf96adcbf9e512ed4";

        String actual = Hmac.sha384("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), "wuriyanto".getBytes());
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testSHA384StreamInputShouldEqualToExpected() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;

        try {

            File burgerFileInput = new File(testdataPath+"/burger.png");
            burgerFileInputStream = new FileInputStream(burgerFileInput);

            String expected = "ea017a4d7998c2eb499fb369fa69e0e548931fafac8fc651116bf51057b34a7f9fc954c9c5f9430edff4e791ec180de9";
            String actual = Hmac.sha384("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), burgerFileInputStream);

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();

            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testSHA384ShouldNotEqualToExpectedWhenKeyIsInvalid() throws Exception {
        String expected = "69b5b98267f760b5dc39cde790adc89358c9a59d7eac7e76c5a9e7acb9c037d0293810251de16afdf96adcbf9e512ed4";

        String actual = Hmac.sha384("abc$#128djdyAgbjau&YAnmcbagryt5v".getBytes(), "wuriyanto".getBytes());
        Assertions.assertNotSame(expected, actual);
    }

    @Test
    public void testSHA384ShouldThrowExceptionWhenKeyLessThanExpected() {
        try {
            Hmac.sha384("abc$#128djdyAgbjau&YAnmcbagryt".getBytes(), "wuriyanto".getBytes());
        } catch(Exception e) {
            Assertions.assertNotNull(e);
        }
    }

    @Test
    public void testSHA512ShouldEqualToExpected() throws Exception {
        String expected = "0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8";

        String actual = Hmac.sha512("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), "wuriyanto".getBytes());
        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testSHA512StreamInputShouldEqualToExpected() {
        Path baseDir = Paths.get("").toAbsolutePath();
        String testdataPath = Paths.get(baseDir.toString(), "src", "test", "java", "com", "wuriyanto", "jcrypsi", "testdata").toString();

        FileInputStream burgerFileInputStream = null;

        try {

            File burgerFileInput = new File(testdataPath+"/burger.png");
            burgerFileInputStream = new FileInputStream(burgerFileInput);

            String expected = "37e382d02e163c2b985030566af69f2cf45abfc089710e32060127a4d55d5d3614af84b0e05293b5a3615b2d54f88e4b24dbcdfe37fac21c6fd75395e604706f";
            String actual = Hmac.sha512("abc$#128djdyAgbjau&YAnmcbagryt5x".getBytes(), burgerFileInputStream);

            Assertions.assertEquals(expected, actual);
        } catch(Exception e) {
            Assertions.assertNull(e);
        } finally {
            try {
                if (burgerFileInputStream != null)
                    burgerFileInputStream.close();

            } catch (Exception e) {
               Assertions.assertNull(e);
            }
        }
    }

    @Test
    public void testSHA512ShouldNotEqualToExpectedWhenKeyIsInvalid() throws Exception {
        String expected = "0084af8c8d831581b30f3ef2a250355bb04f2b2ca632d656ab8dce2b34692e5238ed19f7638070a115196dd928dfff3717dddf9d072ae9c26716c8faa11a25f8";

        String actual = Hmac.sha512("abc$#128djdyAgbjau&YAnmcbagryt5v".getBytes(), "wuriyanto".getBytes());
        Assertions.assertNotSame(expected, actual);
    }

    @Test
    public void testSHA512ShouldThrowExceptionWhenKeyLessThanExpected() {
        try {
            Hmac.sha512("abc$#128djdyAgbjau&YAnmcbagryt".getBytes(), "wuriyanto".getBytes());
        } catch(Exception e) {
            Assertions.assertNotNull(e);
        }
    }
}

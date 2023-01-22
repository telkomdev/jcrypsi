package com.wuriyanto.jcrypsi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class DigestTest {

    @Test
    public void testMD5ShouldEqualToExpected() throws Exception {
        String expected = "60e1bc04fa194a343b50ce67f4afcff8"; 

        String actual = Digest.md5("wuriyanto".getBytes());

        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testMD5LongTextShouldEqualToExpected() throws Exception {
        String expected = "2deae4977e23469cb359ff61a74b320d";

        String actual = Digest.md5("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require".getBytes());

        Assertions.assertEquals(expected, actual);     
    }

    @Test
    public void testMD5ShouldNotEqualToExpected() throws Exception {
        String expected = "60e1bc04fa194a343b50ce67f4afcfff";

        String actual = Digest.md5("wuriyanto".getBytes());

        Assertions.assertNotSame(expected, actual);
    }

    @Test
    public void testSHA1ShouldEqualToExpected() throws Exception {
        String expected = "afd2bd72af0c346a2ab14d50746835d3ccd1dd5f";

        String actual = Digest.sha1("wuriyanto".getBytes());

        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testSHA1LongTextShouldEqualToExpected() throws Exception {
        String expected = "d3f2ae5857e2a1a29a835b1b8146555f3c2f0af6";

        String actual = Digest.sha1("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require".getBytes());

        Assertions.assertEquals(expected, actual);     
    }

    @Test
    public void testSHA1ShouldNotEqualToExpected() throws Exception {
        String expected = "afd2bd72af0c346a2ab14d50746835d3ccd1dd55";

        String actual = Digest.sha1("wuriyanto".getBytes());

        Assertions.assertNotSame(expected, actual);
    }

    @Test
    public void testSHA256ShouldEqualToExpected() throws Exception {
        String expected = "7da544fa170151239b9886c0c905736fe3e8b07e68aefaba0633272aee47af87";

        String actual = Digest.sha256("wuriyanto".getBytes());

        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testSHA256LongTextShouldEqualToExpected() throws Exception {
        String expected = "0dedb636c97ff73bb932996abbad9bdef161b68c6696784f88c1fcf0794338d3";

        String actual = Digest.sha256("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require".getBytes());

        Assertions.assertEquals(expected, actual);     
    }

    @Test
    public void testSHA256ShouldNotEqualToExpected() throws Exception {
        String expected = "7da544fa170151239b9886c0c905736fe3e8b07e68aefaba0633272aee47af88";

        String actual = Digest.sha1("wuriyanto".getBytes());

        Assertions.assertNotSame(expected, actual);
    }

    @Test
    public void testSHA384ShouldEqualToExpected() throws Exception {
        String expected = "2bf236501ecea775cd0eac6da0632eb236e514f29c2aff06a42819fe3b1f3d5b8aefe8c1608a8f5a4d832090902f84a1";

        String actual = Digest.sha384("wuriyanto".getBytes());

        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testSHA384LongTextShouldEqualToExpected() throws Exception {
        String expected = "658eb97762ac1fd44d9062cf49014269cf87ea4938bdd0ae3193ce6375942f2942d75a6863aea55f8149cf0b13d311b6";

        String actual = Digest.sha384("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require".getBytes());

        Assertions.assertEquals(expected, actual);     
    }

    @Test
    public void testSHA384ShouldNotEqualToExpected() throws Exception {
        String expected = "2bf236501ecea775cd0eac6da0632eb236e514f29c2aff06a42819fe3b1f3d5b8aefe8c1608a8f5a4d832090902f84aa";

        String actual = Digest.sha384("wuriyanto".getBytes());

        Assertions.assertNotSame(expected, actual);
    }

    @Test
    public void testSHA512ShouldEqualToExpected() throws Exception {
        String expected = "5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a206";

        String actual = Digest.sha512("wuriyanto".getBytes());

        Assertions.assertEquals(expected, actual);
    }

    @Test
    public void testSHA512LongTextShouldEqualToExpected() throws Exception {
        String expected = "7dbd3db1159a2ddb2a3be939a88f6042948b90b032eb8a02a65ede6dd50226fa708827364c164fdcb16f29cc7d71231e1fc5089b4a96f6a42a6aea4168986e61";

        String actual = Digest.sha512("In cryptography, a hybrid cryptosystem is one which combines the convenience of a public-key cryptosystem with the efficiency of a symmetric-key cryptosystem.[1] Public-key cryptosystems are convenient in that they do not require".getBytes());

        Assertions.assertEquals(expected, actual);     
    }

    @Test
    public void testSHA512ShouldNotEqualToExpected() throws Exception {
        String expected = "5adf884c57a5dc4f353bb08a138953e98320c35843ec86dd42e866e9111f39f502dd250a31f421c9eae8b0593540c30b4ecba6f7f5356632aeea308ee5a5a202";

        String actual = Digest.sha512("wuriyanto".getBytes());

        Assertions.assertNotSame(expected, actual);
    }
}

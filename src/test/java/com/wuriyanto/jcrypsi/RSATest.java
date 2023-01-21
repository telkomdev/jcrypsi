package com.wuriyanto.jcrypsi;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class RSATest extends TestCase {
    
    public RSATest(String testName) {
        super(testName);
    }

    public static Test suite() {
        return new TestSuite( RSATest.class );
    }

    public void testGenerateRSAKeyPairsShouldSucceed() throws Exception {
        RSA rsa = new RSA(RSA.KEY_SIZE_2KB);

        rsa.generateKeyPair();

        assertNotNull(rsa.getPrivateKey());
        assertNotNull(rsa.getPublicKey());

        assertNotNull(rsa.exportPKCS8PrivateKeyToBase64());
        assertNotNull(rsa.exportPKIXPublicKeyToBase64());

        assertNotNull(rsa.exportPKCS8PrivateKeyToHexStr());
        assertNotNull(rsa.exportPKIXPublicKeyToHexStr());
    }
}

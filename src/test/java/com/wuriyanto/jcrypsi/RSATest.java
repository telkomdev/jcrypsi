package com.wuriyanto.jcrypsi;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RSATest {

    @Test
    public void testGenerateRSAKeyPairsShouldSucceed() throws Exception {
        RSA rsa = new RSA(RSA.KEY_SIZE_2KB);

        rsa.generateKeyPair();

        Assertions.assertNotNull(rsa.getPrivateKey());
        Assertions.assertNotNull(rsa.getPublicKey());

        Assertions.assertNotNull(rsa.exportPKCS8PrivateKeyToBase64());
        Assertions.assertNotNull(rsa.exportPKIXPublicKeyToBase64());

        Assertions.assertNotNull(rsa.exportPKCS8PrivateKeyToHexStr());
        Assertions.assertNotNull(rsa.exportPKIXPublicKeyToHexStr());
    }
}

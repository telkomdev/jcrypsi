package com.wuriyanto.jcrypsi;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

public class AESTest extends TestCase {
    
    public AESTest(String testName) {
        super(testName);
    }

    public static Test suite() {
        return new TestSuite( AESTest.class );
    }

    public void testDummyTestAes() {
        assertTrue(true);
    }
}

package com.example.encryption.hibbe.llw16a;

import cn.edu.buaa.crypto.encryption.hibbe.llw16a.HIBBELLW16aEngine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Test Liu-Liu-Wu prime-order HIBBE scheme.
 */

public class HIBBELLW16aEngineJUnitTest extends TestCase {
    private HIBBELLW16aEngine engine;
    private HIBBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        this.engine = HIBBELLW16aEngine.getInstance();
        this.engineJUnitTest = new HIBBEEngineJUnitTest(engine);
    }

    public void testHIBBELLW16aEngine() {
        System.out.println("Test " + engine.getEngineName());
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

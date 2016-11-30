package com.example.access.lsss.lw10;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import com.example.TestUtils;
import com.example.access.AccessControlEngineTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/7/20.
 *
 * Lewko-Waters LSSS engine test.
 */

public class LSSSLW10EngineJUnitTest extends TestCase {
    private AccessControlEngineTest accessControlEngineTest;

    public void setUp() {
        accessControlEngineTest = new AccessControlEngineTest(
                LSSSLW10Engine.getInstance(),
                PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testAccessPolicy() {
        accessControlEngineTest.runAllTests();
    }
}

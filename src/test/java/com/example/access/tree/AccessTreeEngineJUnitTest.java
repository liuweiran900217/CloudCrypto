package com.example.access.tree;

import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import com.example.TestUtils;
import com.example.access.AccessControlEngineTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.junit.Ignore;

/**
 * Created by Weiran Liu on 2016/7/20.
 *
 * Access tree engine test.
 */
@Ignore
public class AccessTreeEngineJUnitTest extends TestCase {
    private AccessControlEngineTest accessControlEngineTest;

    public void setUp() {
        accessControlEngineTest = new AccessControlEngineTest(
                AccessTreeEngine.getInstance(),
                PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testAccessPolicy() {
        accessControlEngineTest.runAllTests();
    }
}

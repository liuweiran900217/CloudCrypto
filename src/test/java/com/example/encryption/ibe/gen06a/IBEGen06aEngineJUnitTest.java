package com.example.encryption.ibe.gen06a;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.IBEGen06aEngine;
import com.example.TestUtils;
import com.example.encryption.ibe.IBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CPA-secure IBE engine test.
 */
public class IBEGen06aEngineJUnitTest extends TestCase {
    private IBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        IBEEngine engine = IBEGen06aEngine.getInstance();
        engineJUnitTest = new IBEEngineJUnitTest(engine);
    }

    public void testIBELW10Engine() {
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

package com.example.encryption.ibe.gen06b;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.IBEGen06bEngine;
import com.example.TestUtils;
import com.example.encryption.ibe.IBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Gentry CCA2-secure IBE engine test.
 */
public class IBEGen06bEngineJUnitTest extends TestCase {
    private IBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        IBEEngine engine = IBEGen06bEngine.getInstance();
        engineJUnitTest = new IBEEngineJUnitTest(engine);
    }

    public void testEngine() {
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

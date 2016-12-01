package com.example.encryption.ibe.bf01b;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.IBEBF01bEngine;
import com.example.TestUtils;
import com.example.encryption.ibe.IBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Frankelin CCA2-secure IBE test case.
 */
public class IBEBF01bEngineJUnitTest extends TestCase {
    private IBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        IBEEngine engine = IBEBF01bEngine.getInstance();
        engineJUnitTest = new IBEEngineJUnitTest(engine);
    }

    public void testIBELW10Engine() {
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

package com.example.encryption.ibe.bf01a;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.IBEBF01aEngine;
import com.example.TestUtils;
import com.example.encryption.ibe.IBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Frankelin IBE engine test.
 */
public class IBEBF01aEngineJUnitTest extends TestCase {
    private IBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        IBEEngine engine = IBEBF01aEngine.getInstance();
        engineJUnitTest = new IBEEngineJUnitTest(engine);
    }

    public void tesEngine() {
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

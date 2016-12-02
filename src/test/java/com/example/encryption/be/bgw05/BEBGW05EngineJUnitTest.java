package com.example.encryption.be.bgw05;

import cn.edu.buaa.crypto.encryption.be.BEEngine;
import cn.edu.buaa.crypto.encryption.be.bgw05.BEBGW05Engine;
import com.example.TestUtils;
import com.example.encryption.be.BEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/12/3.
 *
 * Boneh-Gentry-Waters BE unit test.
 */
public class BEBGW05EngineJUnitTest extends TestCase {
    private BEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        BEEngine engine = BEBGW05Engine.getInstance();
        this.engineJUnitTest = new BEEngineJUnitTest(engine);
    }

    public void testEngine() {
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}
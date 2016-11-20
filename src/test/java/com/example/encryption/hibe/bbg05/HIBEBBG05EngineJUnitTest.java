package com.example.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import com.example.TestUtils;
import com.example.encryption.hibe.HIBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE engine.
 */
public class HIBEBBG05EngineJUnitTest extends TestCase {
    private HIBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        HIBEEngine engine = HIBEBBG05Engine.getInstance();
        this.engineJUnitTest = new HIBEEngineJUnitTest(engine);
    }

    public void testHIBEBBG05Engine() {
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}
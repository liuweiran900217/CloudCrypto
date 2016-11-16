package com.example.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import com.example.TestUtils;
import com.example.encryption.hibe.HIBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE engine.
 */
public class HIBEBBG05EngineTest {
    public static void main(String[] args) {
        HIBEEngine engine = HIBEBBG05Engine.getInstance();
        HIBEEngineTest engineTest = new HIBEEngineTest(engine);

        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
        engineTest.processTest(pairingParameters, 8);
    }
}
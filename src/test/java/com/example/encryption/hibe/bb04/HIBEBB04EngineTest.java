package com.example.encryption.hibe.bb04;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import com.example.TestUtils;
import com.example.encryption.hibe.HIBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen HIBBE engine test.
 */
public class HIBEBB04EngineTest {
    public static void main(String[] args) {
        HIBEEngine engine = HIBEBB04Engine.getInstance();
        HIBEEngineTest engineTest = new HIBEEngineTest(engine);

        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
        engineTest.processTest(pairingParameters);
    }
}

package com.example.encryption.ibe.lw10;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.lw10.IBELW10Engine;
import com.example.TestUtils;
import com.example.encryption.ibe.IBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 16/5/7.
 *
 * Lewko-Sahai-Waters Online/Offline Revocation Encryption engine test.
 */
public class IBELW10EngineTest {
    public static void main(String[] args) {
        IBEEngine engine = IBELW10Engine.getInstance();
        IBEEngineTest engineTest = new IBEEngineTest(engine);

        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128);
        engineTest.processTest(pairingParameters);
    }
}

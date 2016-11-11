package com.example.encryption.hibbe.llw17;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.HIBBELLW17Engine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE engine test.
 */
public class HIBBELLW17EngineTest {
    public static void main(String[] args) {
        HIBBEEngine engine = HIBBELLW17Engine.getInstance();
        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine);
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128);
        engineTest.processTest(pairingParameters);
    }
}

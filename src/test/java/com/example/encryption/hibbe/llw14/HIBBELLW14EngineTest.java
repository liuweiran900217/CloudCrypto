package com.example.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * 2014 Liu-Liu-Wu HIBBE engine test.
 */
public class HIBBELLW14EngineTest {
    public static void main(String[] args) {
        HIBBEEngine engine = HIBBELLW14Engine.getInstance();
        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine);
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128);
        engineTest.processTest(pairingParameters);
    }
}

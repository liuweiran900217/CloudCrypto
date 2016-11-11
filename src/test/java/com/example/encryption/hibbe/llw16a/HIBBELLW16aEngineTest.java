package com.example.encryption.hibbe.llw16a;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.HIBBELLW16aEngine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Test Liu-Liu-Wu prime-order HIBBE scheme.
 */
public class HIBBELLW16aEngineTest {
    public static void main(String[] args) {
        HIBBEEngine engine = HIBBELLW16aEngine.getInstance();
        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine);
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128);
        engineTest.processTest(pairingParameters);
    }
}

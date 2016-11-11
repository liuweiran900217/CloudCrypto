package com.example.encryption.hibbe.llw16b;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.HIBBELLW16bEngine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE engine test.
 */
public class HIBBELLW16bEngineTest {
    public static void main(String[] args) {
        HIBBEEngine engine = HIBBELLW16bEngine.getInstance();
        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine);
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
        engineTest.processTest(pairingParameters);
    }
}

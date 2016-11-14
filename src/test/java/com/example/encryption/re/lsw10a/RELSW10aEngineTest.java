package com.example.encryption.re.lsw10a;

import cn.edu.buaa.crypto.encryption.re.REEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.RELSW10aEngine;
import com.example.TestUtils;
import com.example.encryption.re.REEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters Revocation scheme test.
 */
public class RELSW10aEngineTest {
    public static void main(String[] args) {
        REEngine engine = RELSW10aEngine.getInstance();
        REEngineTest engineTest = new REEngineTest(engine);

        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
        engineTest.processTest(pairingParameters);
    }
}

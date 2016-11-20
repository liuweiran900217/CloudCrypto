package com.example.encryption.re.lsw10a;

import cn.edu.buaa.crypto.encryption.re.REEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.RELSW10aEngine;
import com.example.TestUtils;
import com.example.encryption.re.REEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters Revocation scheme test.
 */
public class RELSW10aEngineJUnitTest extends TestCase {
    private  REEngineJUnitTest engineJUnitTest;

    public void setUp() {
        REEngine engine = RELSW10aEngine.getInstance();
        engineJUnitTest = new REEngineJUnitTest(engine);
    }

    public void testRELSW10aEngine() {
        engineJUnitTest.processTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

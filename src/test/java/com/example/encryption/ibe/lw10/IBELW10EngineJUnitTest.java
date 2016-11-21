package com.example.encryption.ibe.lw10;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.lw10.IBELW10Engine;
import com.example.TestUtils;
import com.example.encryption.ibe.IBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.junit.Ignore;

/**
 * Created by Weiran Liu on 16/5/7.
 *
 * Lewko-Sahai-Waters Online/Offline Revocation Encryption engine test.
 */
@Ignore
public class IBELW10EngineJUnitTest extends TestCase {
    private IBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        IBEEngine engine = IBELW10Engine.getInstance();
        engineJUnitTest = new IBEEngineJUnitTest(engine);
    }

    public void testIBELW10Engine() {
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128));
    }
}

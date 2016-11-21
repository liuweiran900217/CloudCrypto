package com.example.encryption.ibbe.del07;

import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import cn.edu.buaa.crypto.encryption.ibbe.del07.IBBEDel07Engine;
import com.example.TestUtils;
import com.example.encryption.ibbe.IBBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.junit.Ignore;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Delerablée IBBE engine test.
 */
@Ignore
public class IBBEDel07EngineJUnitTest extends TestCase {
    private IBBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        IBBEEngine engine = IBBEDel07Engine.getInstance();
        this.engineJUnitTest = new IBBEEngineJUnitTest(engine);
    }

    public void testIBBEDel07Engine() {
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

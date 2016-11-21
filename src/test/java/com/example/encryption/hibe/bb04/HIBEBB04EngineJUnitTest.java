package com.example.encryption.hibe.bb04;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import com.example.TestUtils;
import com.example.encryption.hibe.HIBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.junit.Ignore;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen HIBBE engine test.
 */
@Ignore
public class HIBEBB04EngineJUnitTest extends TestCase {
    private HIBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        HIBEEngine engine = HIBEBB04Engine.getInstance();
        this.engineJUnitTest = new HIBEEngineJUnitTest(engine);
    }

    public void testHIBEBB04Engine() {
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

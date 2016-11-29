package com.example.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * 2014 Liu-Liu-Wu HIBBE engine test.
 */

public class HIBBELLW14EngineJUnitTest extends TestCase {
    private HIBBELLW14Engine engine;
    private HIBBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        this.engine = HIBBELLW14Engine.getInstance();
        this.engineJUnitTest = new HIBBEEngineJUnitTest(engine);
    }

    public void testHIBBELLW14Engine() {
        System.out.println("Test " + engine.getEngineName());
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128));
    }
}

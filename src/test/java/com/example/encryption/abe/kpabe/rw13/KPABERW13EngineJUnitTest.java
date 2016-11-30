package com.example.encryption.abe.kpabe.rw13;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.KPABERW13Engine;
import com.example.TestUtils;
import com.example.encryption.abe.kpabe.KPABEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Rouselakis-Waters KP-ABE engine test.
 */
public class KPABERW13EngineJUnitTest extends TestCase {
    private KPABEEngine engine;
    private KPABEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        this.engine = KPABERW13Engine.getInstance();
        this.engineJUnitTest = new KPABEEngineJUnitTest(engine);
    }

    public void testUsingAccessTree() {
        System.out.println("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
        engine.setAccessControlEngine(AccessTreeEngine.getInstance());
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testUsingLSSS() {
        System.out.println("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
        engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

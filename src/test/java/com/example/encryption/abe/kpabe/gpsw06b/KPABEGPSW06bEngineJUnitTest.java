package com.example.encryption.abe.kpabe.gpsw06b;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.KPABEGPSW06bEngine;
import com.example.TestUtils;
import com.example.encryption.abe.kpabe.KPABEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles engine test.
 */
public class KPABEGPSW06bEngineJUnitTest extends TestCase {
    private KPABEEngine engine;
    private KPABEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        this.engine = KPABEGPSW06bEngine.getInstance();
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

package com.example.encryption.abe.kpabe.gpsw06a;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.KPABEGPSW06aEngine;
import com.example.TestUtils;
import com.example.encryption.abe.kpabe.KPABEEngineTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE engine test.
 */
public class KPABEGPSW06aEngineTest {
    public static void main(String[] args) {
        KPABEEngine engine = KPABEGPSW06aEngine.getInstance();
        KPABEEngineTest engineTest = new KPABEEngineTest(engine);

        System.out.println("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
        engine.setAccessControlEngine(AccessTreeEngine.getInstance());
        engineTest.processTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
        System.out.println();

        System.out.println("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
        engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
        engineTest.processTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
        System.out.println();
    }
}

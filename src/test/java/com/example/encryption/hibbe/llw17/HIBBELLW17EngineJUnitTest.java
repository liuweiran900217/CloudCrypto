package com.example.encryption.hibbe.llw17;

import cn.edu.buaa.crypto.encryption.hibbe.llw17.HIBBELLW17Engine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.junit.Ignore;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE engine test.
 */
@Ignore
public class HIBBELLW17EngineJUnitTest extends TestCase {
    private HIBBELLW17Engine engine;
    private HIBBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        this.engine = HIBBELLW17Engine.getInstance();
        this.engineJUnitTest = new HIBBEEngineJUnitTest(engine);
    }

    public void testHIBBELLW17WithSHA256() {
        Digest sha256Digest = new SHA256Digest();
        System.out.println("Test " + engine.getEngineName() + " using " + sha256Digest.getAlgorithmName());
        engine.setDigest(sha256Digest);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128));
    }

    public void testHIBBELLW17WithSHA512() {
        Digest sha512Digest = new SHA512Digest();
        System.out.println("Test " + engine.getEngineName() + " using " + sha512Digest.getAlgorithmName());
        engine.setDigest(sha512Digest);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128));
    }
}

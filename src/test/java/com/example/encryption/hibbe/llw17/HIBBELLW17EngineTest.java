package com.example.encryption.hibbe.llw17;

import cn.edu.buaa.crypto.encryption.hibbe.llw17.HIBBELLW17Engine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE engine test.
 */
public class HIBBELLW17EngineTest {
    public static void main(String[] args) {
        HIBBELLW17Engine engine = HIBBELLW17Engine.getInstance();
        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine);

        Digest sha256Digest = new SHA256Digest();
        System.out.println("Test " + engine.getEngineName() + " using " + sha256Digest.getAlgorithmName());
        engine.setDigest(sha256Digest);
        engineTest.processTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128));
        System.out.println();

        Digest sha512Digest = new SHA512Digest();
        System.out.println("Test " + engine.getEngineName() + " using " + sha512Digest.getAlgorithmName());
        engine.setDigest(sha512Digest);
        engineTest.processTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128));
        System.out.println();
    }
}

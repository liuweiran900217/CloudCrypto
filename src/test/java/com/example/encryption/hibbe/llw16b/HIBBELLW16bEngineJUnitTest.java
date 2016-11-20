package com.example.encryption.hibbe.llw16b;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.HIBBELLW16bEngine;
import cn.edu.buaa.crypto.signature.pks.PairingDigestSigner;
import cn.edu.buaa.crypto.signature.pks.PairingSigner;
import cn.edu.buaa.crypto.signature.pks.bb08.BB08SignKeyPairGenerationParameter;
import cn.edu.buaa.crypto.signature.pks.bb08.BB08SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bb08.BB08Signer;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01SignKeyPairGenerationParameter;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01Signer;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineJUnitTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE engine test.
 */
public class HIBBELLW16bEngineJUnitTest extends TestCase {
    private HIBBELLW16bEngine engine;
    private HIBBEEngineJUnitTest engineJUnitTest;

    public void setUp() {
        this.engine = HIBBELLW16bEngine.getInstance();
        this.engineJUnitTest = new HIBBEEngineJUnitTest(engine);
    }

    public void testHIBBELLW16bEngineWithBB08() {
        PairingSigner bb08PairingSigner = new BB08Signer();
        Signer bb08Signer = new PairingDigestSigner(bb08PairingSigner, new SHA256Digest());
        PairingKeyPairGenerator bb08SignKeyPairGenerator = new BB08SignKeyPairGenerator();
        KeyGenerationParameters bb08SignKeyPairGenerationParameter =
                new BB08SignKeyPairGenerationParameter(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
        System.out.println("Test " + engine.getEngineName() + " using " + bb08PairingSigner.getEngineName());
        engine.setSigner(bb08Signer, bb08SignKeyPairGenerator, bb08SignKeyPairGenerationParameter);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testHIBBELLW16bEngineWithBLS01() {
        PairingSigner bls01PairingSigner = new BLS01Signer();
        Signer bls01Signer = new PairingDigestSigner(bls01PairingSigner, new SHA256Digest());
        PairingKeyPairGenerator bls01SignKeyPairGenerator = new BLS01SignKeyPairGenerator();
        KeyGenerationParameters bls01SignKeyPairGenerationParameter =
                new BLS01SignKeyPairGenerationParameter(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
        System.out.println("Test " + engine.getEngineName() + " using " + bls01PairingSigner.getEngineName());
        engine.setSigner(bls01Signer, bls01SignKeyPairGenerator, bls01SignKeyPairGenerationParameter);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

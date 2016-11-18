package com.example.encryption.hibbe.llw16b;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
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
import com.example.encryption.hibbe.HIBBEEngineTest;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE engine test.
 */
public class HIBBELLW16bEngineTest {
    public static void main(String[] args) {
        HIBBELLW16bEngine engine = HIBBELLW16bEngine.getInstance();
        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine);

        PairingSigner bb08PairingSigner = new BB08Signer();
        Signer bb08Signer = new PairingDigestSigner(bb08PairingSigner, new SHA256Digest());
        AsymmetricKeySerPairGenerator bb08SignKeyPairGenerator = new BB08SignKeyPairGenerator();
        KeyGenerationParameters bb08SignKeyPairGenerationParameter =
                new BB08SignKeyPairGenerationParameter(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
        System.out.println("Test " + engine.getEngineName() + " using " + bb08PairingSigner.getEngineName());
        engine.setSigner(bb08Signer, bb08SignKeyPairGenerator, bb08SignKeyPairGenerationParameter);
        engineTest.processTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
        System.out.println();

        PairingSigner bls01PairingSigner = new BLS01Signer();
        Signer bls01Signer = new PairingDigestSigner(bls01PairingSigner, new SHA256Digest());
        AsymmetricKeySerPairGenerator bls01SignKeyPairGenerator = new BLS01SignKeyPairGenerator();
        KeyGenerationParameters bls01SignKeyPairGenerationParameter =
                new BLS01SignKeyPairGenerationParameter(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
        System.out.println("Test " + engine.getEngineName() + " using " + bls01PairingSigner.getEngineName());
        engine.setSigner(bls01Signer, bls01SignKeyPairGenerator, bls01SignKeyPairGenerationParameter);
        engineTest.processTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
        System.out.println();
    }
}

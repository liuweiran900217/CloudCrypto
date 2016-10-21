package com.example.signature.pks;

import cn.edu.buaa.crypto.algebra.generators.PairingParametersGenerator;
import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.signature.pks.PairingDigestSigner;
import cn.edu.buaa.crypto.signature.pks.bb04.BB04SignKeyPairGenerationParameters;
import cn.edu.buaa.crypto.signature.pks.bb04.BB04SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bb04.BB04Signer;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01SignKeyPairGenerationParameters;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01Signer;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Public key signature test.
 */
public class PKSSignerTest {
    private AsymmetricCipherKeyPairGenerator asymmetricCipherKeyPairGenerator;
    private Signer pairingSigner;

    private PKSSignerTest(AsymmetricCipherKeyPairGenerator asymmetricCipherKeyPairGenerator, Signer pairingSigner) {
        this.asymmetricCipherKeyPairGenerator = asymmetricCipherKeyPairGenerator;
        this.pairingSigner = pairingSigner;
    }

    public void processTest() {
        //KeyGen
        AsymmetricCipherKeyPair keyPair = asymmetricCipherKeyPairGenerator.generateKeyPair();
        AsymmetricKeyParameter publicKey = keyPair.getPublic();
        AsymmetricKeyParameter secretKey = keyPair.getPrivate();

        try {
            //signature
            byte[] message = "Message".getBytes();
            pairingSigner.init(true, secretKey);
            pairingSigner.update(message, 0, message.length);
            byte[] signature = pairingSigner.generateSignature();

            //verify
            pairingSigner.init(false, publicKey);
            pairingSigner.update(message, 0, message.length);
            if (!pairingSigner.verifySignature(signature)) {
                System.out.println("cannot verify valid signature, test abort...");
                System.exit(0);
            }
        } catch (CryptoException e) {
            e.printStackTrace();
        }

        System.out.println("Test pass.");
    }

    public static void main(String[] args) {
        PairingParametersGenerationParameters pairingParametersGenerationParameters =
                new PairingParametersGenerationParameters(
                        PairingParametersGenerationParameters.PairingType.TYPE_A,
                        PairingParametersGenerationParameters.DEFAULT_R_BIT_LENGTH,
                        PairingParametersGenerationParameters.DEFAULT_Q_BIT_LENGTH);
        PairingParametersGenerator pairingParametersGenerator = new PairingParametersGenerator();
        pairingParametersGenerator.init(pairingParametersGenerationParameters);
        PairingParameters pairingParameters = pairingParametersGenerator.generateParameters();

        //test Boneh-Boyen signature.
        System.out.println("Test Boneh-Boyen signature.");
        AsymmetricCipherKeyPairGenerator signKeyPairGenerator = new BB04SignKeyPairGenerator();
        signKeyPairGenerator.init(new BB04SignKeyPairGenerationParameters(pairingParameters));
        Signer signer = new PairingDigestSigner(new BB04Signer(), new SHA256Digest());
        new PKSSignerTest(signKeyPairGenerator, signer).processTest();

        //test Boneh-Lynn-Shacham signature.
        System.out.println("Test Boneh-Lynn-Shacham signature.");
        signKeyPairGenerator = new BLS01SignKeyPairGenerator();
        signKeyPairGenerator.init(new BLS01SignKeyPairGenerationParameters(pairingParameters));
        signer = new PairingDigestSigner(new BLS01Signer(), new SHA256Digest());
        new PKSSignerTest(signKeyPairGenerator, signer).processTest();
    }
}

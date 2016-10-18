package com.example.signature.pks;

import cn.edu.buaa.crypto.signature.pks.PairingBasedDigestSigner;
import cn.edu.buaa.crypto.signature.pks.PairingSignKeyPairGenerationParameters;
import cn.edu.buaa.crypto.signature.pks.bb04.BB04SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bb04.BB04Signer;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01Signer;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01SignKeyPairGenerator;
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
        AsymmetricCipherKeyPairGenerator signKeyPairGenerator = new BB04SignKeyPairGenerator();
        signKeyPairGenerator.init(new PairingSignKeyPairGenerationParameters(160, 256));
        Signer signer = new PairingBasedDigestSigner(new BB04Signer(), new SHA256Digest());
        new PKSSignerTest(signKeyPairGenerator, signer).processTest();
    }
}

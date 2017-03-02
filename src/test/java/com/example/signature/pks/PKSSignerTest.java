package com.example.signature.pks;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.signature.pks.PairingDigestSigner;
import cn.edu.buaa.crypto.signature.pks.bb04.BB04SignKeyPairGenerationParameter;
import cn.edu.buaa.crypto.signature.pks.bb04.BB04SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bb04.BB04Signer;
import cn.edu.buaa.crypto.signature.pks.bb08.BB08SignKeyPairGenerationParameter;
import cn.edu.buaa.crypto.signature.pks.bb08.BB08SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bb08.BB08Signer;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01SignKeyPairGenerationParameter;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01SignKeyPairGenerator;
import cn.edu.buaa.crypto.signature.pks.bls01.BLS01Signer;
import cn.edu.buaa.crypto.utils.PairingUtils;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Public key signature test.
 */
public class PKSSignerTest extends TestCase {
    private PairingKeyPairGenerator asymmetricKeySerPairGenerator;
    private Signer signer;

    private void processTest() {
        //KeyGen
        PairingKeySerPair keyPair = this.asymmetricKeySerPairGenerator.generateKeyPair();
        PairingKeySerParameter publicKey = keyPair.getPublic();
        PairingKeySerParameter secretKey = keyPair.getPrivate();

        System.out.println("========================================");
        System.out.println("Test signer functionality");
        try {
            //signature
            byte[] message = "Message".getBytes();
            signer.init(true, secretKey);
            signer.update(message, 0, message.length);
            byte[] signature = signer.generateSignature();
            System.out.println("Signature length = " + signature.length);

            byte[] messagePrime = "MessagePrime".getBytes();
            signer.init(true, secretKey);
            signer.update(messagePrime, 0, messagePrime.length);
            byte[] signaturePrime = signer.generateSignature();
            System.out.println("Signature' length = " + signature.length);

            //verify
            signer.init(false, publicKey);
            signer.update(message, 0, message.length);
            if (!signer.verifySignature(signature)) {
                System.out.println("cannot verify valid signature, test abort...");
                System.exit(0);
            }
            signer.init(false, publicKey);
            signer.update(message, 0, message.length);
            if (signer.verifySignature(signaturePrime)) {
                System.out.println("Verify passed for invalid signature, test abort...");
                System.exit(0);
            }
        } catch (CryptoException e) {
            e.printStackTrace();
        }
        System.out.println("Pairing signer functionality test pass.");

        System.out.println("========================================");
        System.out.println("Test signer parameters serialization & de-serialization.");
        try {
            //serialize public key
            System.out.println("Test serialize & de-serialize public key.");
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            assertEquals(publicKey, anPublicKey);

            //serialize secret key
            System.out.println("Test serialize & de-serialize secret keys.");
            //serialize sk4
            byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
            CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
            assertEquals(secretKey, anSecretKey);

            System.out.println("Signer parameter serialization tests passed.");
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void testBLS01Signer() {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_f_160);
        System.out.println("Test Boneh-Lynn-Shacham 2001 signature.");
        this.asymmetricKeySerPairGenerator = new BLS01SignKeyPairGenerator();
        this.asymmetricKeySerPairGenerator.init(new BLS01SignKeyPairGenerationParameter(pairingParameters));
        this.signer = new PairingDigestSigner(new BLS01Signer(), new SHA256Digest());
        this.processTest();
    }

    public void testBB04Signer() {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
        System.out.println("Test Boneh-Boyen 2004 signature.");
        this.asymmetricKeySerPairGenerator = new BB04SignKeyPairGenerator();
        this.asymmetricKeySerPairGenerator.init(new BB04SignKeyPairGenerationParameter(pairingParameters));
        this.signer = new PairingDigestSigner(new BB04Signer(), new SHA256Digest());
        this.processTest();
    }

    public void testBB08Signer() {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(PairingUtils.PATH_a_160_512);
        System.out.println("Test Boneh-Boyen 2008 signature.");
        this.asymmetricKeySerPairGenerator = new BB08SignKeyPairGenerator();
        this.asymmetricKeySerPairGenerator.init(new BB08SignKeyPairGenerationParameter(pairingParameters));
        this.signer = new PairingDigestSigner(new BB08Signer(), new SHA256Digest());
        this.processTest();
    }
}

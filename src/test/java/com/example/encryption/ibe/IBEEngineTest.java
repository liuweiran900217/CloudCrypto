package com.example.encryption.ibe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * IBE engine test.
 */
public class IBEEngineTest {
    private IBEEngine engine;

    public IBEEngineTest(IBEEngine engine) {
        this.engine = engine;
    }

    public void processTest(PairingParameters pairingParameters) {
        // Setup
        AsymmetricKeySerPair keyPair = engine.setup(pairingParameters);
        AsymmetricKeySerParameter publicKey = keyPair.getPublic();
        AsymmetricKeySerParameter masterKey = keyPair.getPrivate();

        // KeyGen
        String id_1 = "ID_1";
        String id_2 = "ID_2";

        AsymmetricKeySerParameter skID_1 = engine.keyGen(publicKey, masterKey, id_1);
        AsymmetricKeySerParameter skID_2 = engine.keyGen(publicKey, masterKey, id_2);

        // Encryption
        PairingKeyEncapsulationSerPair ciphertextPairID_1 = engine.encapsulation(publicKey, id_1);
        PairingCipherSerParameter ciphertextID_1 = ciphertextPairID_1.getCiphertext();
        byte[] sessionKeyID_1 = ciphertextPairID_1.getSessionKey();
        String stringSessionKey0 = new String(Hex.encode(sessionKeyID_1));

        System.out.println("======================================");
        System.out.println("Test IBE engine functionality.");
        // Decrypt with correct secret keys
        System.out.println("Test decrypting with correct secret keys.");
        try {
            //Decrypt ciphertext ID_1 using secret key ID_1
            String sessionKey =  new String(Hex.encode(engine.decapsulation(publicKey, skID_1, id_1, ciphertextID_1)));
            assertEquals(stringSessionKey0, sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }

        //Decrypt with incorrect secret keys
        System.out.println("Test decrypting with incorrect secret keys.");
        try {
            //Decrypt ciphertext ID_1 using secret key ID_2
            System.out.println("Test decrypting ciphertext ID_1 using secret key ID_2");
            assertEquals(false, stringSessionKey0.equals(new String(Hex.encode(engine.decapsulation(
                            publicKey, skID_2, id_1, ciphertextID_1)))));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        System.out.println("IBE engine functionality test passed.");
        System.out.println();
        //Test Serialize & deserialize
        System.out.println("======================================");
        System.out.println("Test IBE parameter serialization & de-serialization.");
        try {
            //serialize public key
            System.out.println("Test serialize & de-serialize public key.");
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            assertEquals(publicKey, anPublicKey);

            //serialize master secret key
            System.out.println("Test serialize & de-serialize master secret key.");
            byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
            CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
            assertEquals(masterKey, anMasterKey);

            //serialize secret key
            System.out.println("Test serialize & de-serialize secret key.");
            byte[] byteArraySkID01 = TestUtils.SerCipherParameter(skID_1);
            CipherParameters anSkID_1 = TestUtils.deserCipherParameters(byteArraySkID01);
            assertEquals(skID_1, anSkID_1);

            //serialize ciphertext01
            System.out.println("Test serialize & de-serialize ciphertext.");
            byte[] byteArrayCiphertext01 = TestUtils.SerCipherParameter(ciphertextID_1);
            CipherParameters anCiphertextID_1 = TestUtils.deserCipherParameters(byteArrayCiphertext01);
            assertEquals(ciphertextID_1, anCiphertextID_1);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("IBE parameter serialization tests passed.");
        System.out.println();
    }
}

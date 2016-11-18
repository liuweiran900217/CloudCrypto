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
import org.junit.Assert;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * IBE engine test.
 */
public class IBEEngineTest {
    private static final String identity_1 = "ID_1";
    private static final String identity_2 = "ID_2";

    private IBEEngine engine;

    public IBEEngineTest(IBEEngine engine) {
        this.engine = engine;
    }

    private void test_valid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          String identityForSecretKey, String identityForCiphertext) {
        try {
            test_decapsulation(publicKey, masterKey, identityForSecretKey, identityForCiphertext);
        } catch (Exception e) {
            System.out.println("Valid decapsulation test failed, " +
                    "secret key identity  = " + identityForSecretKey + ", " +
                    "ciphertext identity = " + identityForCiphertext);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_invalid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                            String identityForSecretKey, String identityForCiphertext) {
        try {
            test_decapsulation(publicKey, masterKey, identityForSecretKey, identityForCiphertext);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid decapsulation test failed, " +
                    "secret key identity  = " + identityForSecretKey + ", " +
                    "ciphertext identity = " + identityForCiphertext);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                    String identityForSecretKey, String identityForCiphertext)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityForSecretKey);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (AsymmetricKeySerParameter)anSecretKey;

        //Encryption and serialization
        PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identityForCiphertext);
        byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getCiphertext();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityForCiphertext, ciphertext);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    public void processTest(PairingParameters pairingParameters) {
        try {
            // Setup and serialization
            AsymmetricKeySerPair keyPair = engine.setup(pairingParameters);
            AsymmetricKeySerParameter publicKey = keyPair.getPublic();
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            Assert.assertEquals(publicKey, anPublicKey);
            publicKey = (AsymmetricKeySerParameter) anPublicKey;

            AsymmetricKeySerParameter masterKey = keyPair.getPrivate();
            byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
            CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
            Assert.assertEquals(masterKey, anMasterKey);
            masterKey = (AsymmetricKeySerParameter) anMasterKey;

            //test valid example
            System.out.println("Test valid examples");
            test_valid_decapsulation(publicKey, masterKey, identity_1, identity_1);
            test_valid_decapsulation(publicKey, masterKey, identity_2, identity_2);

            //test valid example
            System.out.println("Test invalid examples");
            test_invalid_decapsulation(publicKey, masterKey, identity_1, identity_2);
            test_invalid_decapsulation(publicKey, masterKey, identity_2, identity_1);
            System.out.println(engine.getEngineName() + " test passed");
        } catch (ClassNotFoundException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        } catch (IOException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        }
    }
}

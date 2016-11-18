package com.example.encryption.hibe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * HIBE engine test procedures. All instances should pass this unit test.
 */
public class HIBEEngineTest {
    private static final String[] identityVector1 = {"ID_1"};
    private static final String[] identityVector12 = {"ID_1", "ID_2"};
    private static final String[] identityVector123 = {"ID_1", "ID_2", "ID_3"};

    private static final String[] identityVector3 = {"ID_3"};
    private static final String[] identityVector31 = {"ID_3", "ID_1"};
    private static final String[] identityVector132 = {"ID_1", "ID_3", "ID_2"};

    private HIBEEngine engine;

    public HIBEEngineTest(HIBEEngine engine) {
        this.engine = engine;
    }

    private void test_valid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          String[] identityVector, String[] identityVectorSet) {
        try {
            test_decapsulation(publicKey, masterKey, identityVector, identityVectorSet);
        } catch (Exception e) {
            System.out.println("Valid decapsulation test failed, " +
                    "identity vector  = " + Arrays.toString(identityVector) + ", " +
                    "iv encapsulation = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_invalid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                            String[] identityVector, String[] identityVectorSet) {
        try {
            test_decapsulation(publicKey, masterKey, identityVector, identityVectorSet);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid decapsulation test failed, " +
                    "identity vector  = " + Arrays.toString(identityVector) + ", " +
                    "iv encapsulation = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                    String[] identityVector, String[] identityVectorEnc)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (AsymmetricKeySerParameter)anSecretKey;

        //Encryption and serialization
        PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identityVectorEnc);
        byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getCiphertext();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityVectorEnc, ciphertext);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void test_delegation_valid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                                     String[] identityVector, String delegateId, String[] identityVectorEnc) {
        try {
            AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
            AsymmetricKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, delegateId);
            byte[] byteArrayDelegateKey = TestUtils.SerCipherParameter(delegateKey);
            CipherParameters anDelegateKey = TestUtils.deserCipherParameters(byteArrayDelegateKey);
            Assert.assertEquals(delegateKey, anDelegateKey);
            delegateKey = (AsymmetricKeySerParameter)anDelegateKey;

            //Encryption and serialization
            PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identityVectorEnc);
            byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
            PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getCiphertext();
            byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            byte[] anSessionKey = engine.decapsulation(publicKey, delegateKey, identityVectorEnc, ciphertext);
            Assert.assertArrayEquals(sessionKey, anSessionKey);
        } catch (Exception e) {
            System.out.println("Valid delegate decapsulation test failed, " +
                    "identity vector  = " + Arrays.toString(identityVector) + ", " +
                    "delegate ident. = " + delegateId + ", " +
                    "iv encapsulation = " + Arrays.toString(identityVectorEnc));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_delegation_invalid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                                       String[] identityVector, String delegateId, String[] identityVectorEnc) {
        try {
            AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
            AsymmetricKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, delegateId);
            byte[] byteArrayDelegateKey = TestUtils.SerCipherParameter(delegateKey);
            CipherParameters anDelegateKey = TestUtils.deserCipherParameters(byteArrayDelegateKey);
            Assert.assertEquals(delegateKey, anDelegateKey);
            delegateKey = (AsymmetricKeySerParameter)anDelegateKey;

            //Encryption and serialization
            PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identityVectorEnc);
            byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
            PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getCiphertext();
            byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            byte[] anSessionKey = engine.decapsulation(publicKey, delegateKey, identityVectorEnc, ciphertext);
            Assert.assertArrayEquals(sessionKey, anSessionKey);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid delegate decapsulation test failed, " +
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "delegate ident. = " + delegateId + ", " +
                    "iv encapsulation = " + Arrays.toString(identityVectorEnc));
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void processTest(PairingParameters pairingParameters) {
        try {
            // Setup and serialization
            AsymmetricKeySerPair keyPair = engine.setup(pairingParameters, identityVector123.length);
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
            test_valid_decapsulation(publicKey, masterKey, identityVector1, identityVector12);
            test_valid_decapsulation(publicKey, masterKey, identityVector1, identityVector123);
            test_valid_decapsulation(publicKey, masterKey, identityVector12, identityVector123);
            test_valid_decapsulation(publicKey, masterKey, identityVector123, identityVector123);
            test_delegation_valid_decapsulation(publicKey, masterKey, identityVector1, "ID_2", identityVector12);
            test_delegation_valid_decapsulation(publicKey, masterKey, identityVector1, "ID_2", identityVector123);
            test_delegation_valid_decapsulation(publicKey, masterKey, identityVector12, "ID_3", identityVector123);

            //test valid example
            System.out.println("Test invalid examples");
            test_invalid_decapsulation(publicKey, masterKey, identityVector3, identityVector1);
            test_invalid_decapsulation(publicKey, masterKey, identityVector31, identityVector1);
            test_invalid_decapsulation(publicKey, masterKey, identityVector31, identityVector123);
            test_invalid_decapsulation(publicKey, masterKey, identityVector132, identityVector123);
            test_delegation_invalid_decapsulation(publicKey, masterKey, identityVector3, "ID_1", identityVector1);
            test_delegation_invalid_decapsulation(publicKey, masterKey, identityVector12, "ID_3", identityVector132);
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

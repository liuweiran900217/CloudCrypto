package com.example.encryption.hibbe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE engine test procedures. All instances should pass this unit test.
 */
public class HIBBEEngineTest {
    private static final String[] identityVector4_satisfied    = {null,    null,   null,   "ID_4", null,   null,   null,   null};
    private static final String[] identityVector46_satisfied   = {null,    null,   null,   "ID_4", null,   "ID_6", null,   null};
    private static final String[] identityVector467_satisfied  = {null,    null,   null,   "ID_4", null,   "ID_6", "ID_7", null};
    private static final String[] identityVector45_unsatisfied = {null,    null,   null,   "ID_4", "ID_5", null,   null,   null};
    private static final String[] identityVector3_unsatisfied  = {"ID_3",  null,   null,   null,   null,   null,   null,   null};
    private static final String[] identityVector31_unsatisfied = {"ID_3",  null,   "ID_1", null,   null,   null,   null,   null};
    private static final String[] identityVectorSet13467  = {"ID_1",  null,   "ID_3", "ID_4", null,   "ID_6", "ID_7", null};

    private HIBBEEngine engine;

    public HIBBEEngineTest(HIBBEEngine engine) {
        this.engine = engine;
    }

    private void test_valid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          String[] identityVector, String[] identityVectorSet) {
        try {
            test_decapsulation(publicKey, masterKey, identityVector, identityVectorSet);
        } catch (Exception e) {
            System.out.println("Valid decapsulation test failed, " +
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "identity v. set = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_delegation_valid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          String[] identityVector, int index, String delegateId, String[] identityVectorSet) {
        try {
            AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
            AsymmetricKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, index, delegateId);
            byte[] byteArrayDelegateKey = TestUtils.SerCipherParameter(delegateKey);
            CipherParameters anDelegateKey = TestUtils.deserCipherParameters(byteArrayDelegateKey);
            Assert.assertEquals(delegateKey, anDelegateKey);
            delegateKey = (AsymmetricKeySerParameter)anDelegateKey;

            //Encryption and serialization
            PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identityVectorSet);
            byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
            PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getCiphertext();
            byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            byte[] anSessionKey = engine.decapsulation(publicKey, delegateKey, identityVectorSet, ciphertext);
            Assert.assertArrayEquals(sessionKey, anSessionKey);
        } catch (Exception e) {
            System.out.println("Valid delegate decapsulation test failed, " +
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "delegate ident. = " + delegateId + ", " +
                    "identity v. set = " + Arrays.toString(identityVectorSet));
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
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "identity v. set = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_delegation_invalid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                                       String[] identityVector, int index, String delegateId, String[] identityVectorSet) {
        try {
            AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
            AsymmetricKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, index, delegateId);
            byte[] byteArrayDelegateKey = TestUtils.SerCipherParameter(delegateKey);
            CipherParameters anDelegateKey = TestUtils.deserCipherParameters(byteArrayDelegateKey);
            Assert.assertEquals(delegateKey, anDelegateKey);
            delegateKey = (AsymmetricKeySerParameter)anDelegateKey;

            //Encryption and serialization
            PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identityVectorSet);
            byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
            PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getCiphertext();
            byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            byte[] anSessionKey = engine.decapsulation(publicKey, delegateKey, identityVectorSet, ciphertext);
            Assert.assertArrayEquals(sessionKey, anSessionKey);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid delegate decapsulation test failed, " +
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "delegate ident. = " + delegateId + ", " +
                    "identity v. set = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                     String[] identityVector, String[] identityVectorSet)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (AsymmetricKeySerParameter)anSecretKey;

        //Encryption and serialization
        PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identityVectorSet);
        byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getCiphertext();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityVectorSet, ciphertext);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    public void processTest(PairingParameters pairingParameters) {
        try {
            // Setup and serialization
            AsymmetricKeySerPair keyPair = engine.setup(pairingParameters, identityVectorSet13467.length);
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
            test_valid_decapsulation(publicKey, masterKey, identityVector4_satisfied, identityVectorSet13467);
            test_valid_decapsulation(publicKey, masterKey, identityVector46_satisfied, identityVectorSet13467);
            test_valid_decapsulation(publicKey, masterKey, identityVector467_satisfied, identityVectorSet13467);
            test_delegation_valid_decapsulation(publicKey, masterKey, identityVector4_satisfied, 5, "ID_6", identityVectorSet13467);
            test_delegation_valid_decapsulation(publicKey, masterKey, identityVector46_satisfied, 6, "ID_7", identityVectorSet13467);

            //test valid example
            System.out.println("Test invalid examples");
            test_invalid_decapsulation(publicKey, masterKey, identityVector45_unsatisfied, identityVectorSet13467);
            test_invalid_decapsulation(publicKey, masterKey, identityVector3_unsatisfied, identityVectorSet13467);
            test_invalid_decapsulation(publicKey, masterKey, identityVector31_unsatisfied, identityVectorSet13467);
            test_delegation_invalid_decapsulation(publicKey, masterKey, identityVector3_unsatisfied, 2, "ID_1", identityVectorSet13467);
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

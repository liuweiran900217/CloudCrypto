package com.example.encryption.hibbe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
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

    private void test_valid_decryption(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          String[] identityVector, String[] identityVectorSet) {
        try {
            test_decryption(pairing, publicKey, masterKey, identityVector, identityVectorSet);
        } catch (Exception e) {
            System.out.println("Valid decryption test failed, " +
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "identity v. set = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_delegation_valid_decryption(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          String[] identityVector, int index, String delegateId, String[] identityVectorSet) {
        try {
            AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
            AsymmetricKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, index, delegateId);
            byte[] byteArrayDelegateKey = TestUtils.SerCipherParameter(delegateKey);
            CipherParameters anDelegateKey = TestUtils.deserCipherParameters(byteArrayDelegateKey);
            Assert.assertEquals(delegateKey, anDelegateKey);
            delegateKey = (AsymmetricKeySerParameter)anDelegateKey;

            //Encryption and serialization
            Element message = pairing.getGT().newRandomElement().getImmutable();
            PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorSet, message);
            byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            Element anMessage = engine.decryption(publicKey, delegateKey, identityVectorSet, ciphertext);
            Assert.assertEquals(message, anMessage);
        } catch (Exception e) {
            System.out.println("Valid decryption decryption test failed, " +
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "delegate ident. = " + delegateId + ", " +
                    "identity v. set = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_invalid_decryption(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          String[] identityVector, String[] identityVectorSet) {
        try {
            test_decryption(pairing, publicKey, masterKey, identityVector, identityVectorSet);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid decryption test failed, " +
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "identity v. set = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_delegation_invalid_decryption(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                                       String[] identityVector, int index, String delegateId, String[] identityVectorSet) {
        try {
            AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
            AsymmetricKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, index, delegateId);
            byte[] byteArrayDelegateKey = TestUtils.SerCipherParameter(delegateKey);
            CipherParameters anDelegateKey = TestUtils.deserCipherParameters(byteArrayDelegateKey);
            Assert.assertEquals(delegateKey, anDelegateKey);
            delegateKey = (AsymmetricKeySerParameter)anDelegateKey;

            //Encryption and serialization
            Element message = pairing.getGT().newRandomElement().getImmutable();
            PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorSet, message);
            byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            Element anMessage = engine.decryption(publicKey, delegateKey, identityVectorSet, ciphertext);
            Assert.assertEquals(message, anMessage);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid delegate decryption test failed, " +
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "delegate ident. = " + delegateId + ", " +
                    "identity v. set = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_decryption(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                     String[] identityVector, String[] identityVectorSet)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (AsymmetricKeySerParameter)anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorSet, message);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        Element anMessage = engine.decryption(publicKey, secretKey, identityVectorSet, ciphertext);
        Assert.assertEquals(message, anMessage);
    }

    public void processTest(PairingParameters pairingParameters) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
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
            test_valid_decryption(pairing, publicKey, masterKey, identityVector4_satisfied, identityVectorSet13467);
            test_valid_decryption(pairing, publicKey, masterKey, identityVector46_satisfied, identityVectorSet13467);
            test_valid_decryption(pairing, publicKey, masterKey, identityVector467_satisfied, identityVectorSet13467);
            test_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector4_satisfied, 5, "ID_6", identityVectorSet13467);
            test_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector46_satisfied, 6, "ID_7", identityVectorSet13467);

            //test valid example
            System.out.println("Test invalid examples");
            test_invalid_decryption(pairing, publicKey, masterKey, identityVector45_unsatisfied, identityVectorSet13467);
            test_invalid_decryption(pairing, publicKey, masterKey, identityVector3_unsatisfied, identityVectorSet13467);
            test_invalid_decryption(pairing, publicKey, masterKey, identityVector31_unsatisfied, identityVectorSet13467);
            test_delegation_invalid_decryption(pairing, publicKey, masterKey, identityVector3_unsatisfied, 2, "ID_1", identityVectorSet13467);
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

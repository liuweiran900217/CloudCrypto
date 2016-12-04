package com.example.encryption.hibe;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
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
public class HIBEEngineJUnitTest extends TestCase {
    private static final String[] identityVector1 = {"ID_1"};
    private static final String[] identityVector12 = {"ID_1", "ID_2"};
    private static final String[] identityVector123 = {"ID_1", "ID_2", "ID_3"};

    private static final String[] identityVector3 = {"ID_3"};
    private static final String[] identityVector31 = {"ID_3", "ID_1"};
    private static final String[] identityVector132 = {"ID_1", "ID_3", "ID_2"};

    private HIBEEngine engine;

    private void try_valid_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                       String[] identityVector, String[] identityVectorSet) {
        try {
            try_decryption(pairing, publicKey, masterKey, identityVector, identityVectorSet);
        } catch (Exception e) {
            System.out.println("Valid decryption test failed, " +
                    "identity vector  = " + Arrays.toString(identityVector) + ", " +
                    "iv encapsulation = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_invalid_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         String[] identityVector, String[] identityVectorSet) {
        try {
            try_decryption(pairing, publicKey, masterKey, identityVector, identityVectorSet);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid decryption test failed, " +
                    "identity vector  = " + Arrays.toString(identityVector) + ", " +
                    "iv encapsulation = " + Arrays.toString(identityVectorSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                 String[] identityVector, String[] identityVectorEnc)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (PairingKeySerParameter)anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorEnc, message);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        Element anMessage = engine.decryption(publicKey, secretKey, identityVectorEnc, ciphertext);
        Assert.assertEquals(message, anMessage);

        //Encapsulation and serialization
        PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityVectorEnc);
        byte[] sessionKey = encapsulationPair.getSessionKey();
        PairingCipherSerParameter header = encapsulationPair.getHeader();
        byte[] byteArrayHeader = TestUtils.SerCipherParameter(header);
        CipherParameters anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
        Assert.assertEquals(anHeader, anHeader);
        header = (PairingCipherSerParameter)anHeader;

        //Decapsulation
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityVectorEnc, header);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void try_delegation_valid_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                                  String[] identityVector, String delegateId, String[] identityVectorEnc) {
        try {
            PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
            PairingKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, delegateId);
            byte[] byteArrayDelegateKey = TestUtils.SerCipherParameter(delegateKey);
            CipherParameters anDelegateKey = TestUtils.deserCipherParameters(byteArrayDelegateKey);
            Assert.assertEquals(delegateKey, anDelegateKey);
            delegateKey = (PairingKeySerParameter)anDelegateKey;

            //Encryption and serialization
            Element message = pairing.getGT().newRandomElement().getImmutable();
            PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorEnc, message);
            byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            Element anMessage = engine.decryption(publicKey, delegateKey, identityVectorEnc, ciphertext);
            Assert.assertEquals(message, anMessage);

            //Encapsulation and serialization
            PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityVectorEnc);
            byte[] sessionKey = encapsulationPair.getSessionKey();
            PairingCipherSerParameter header = encapsulationPair.getHeader();
            byte[] byteArrayHeader = TestUtils.SerCipherParameter(header);
            CipherParameters anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
            Assert.assertEquals(anHeader, anHeader);
            header = (PairingCipherSerParameter)anHeader;

            //Decapsulation
            byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityVectorEnc, header);
            Assert.assertArrayEquals(sessionKey, anSessionKey);
        } catch (Exception e) {
            System.out.println("Valid delegate decryption test failed, " +
                    "identity vector  = " + Arrays.toString(identityVector) + ", " +
                    "delegate ident. = " + delegateId + ", " +
                    "iv encapsulation = " + Arrays.toString(identityVectorEnc));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_delegation_invalid_decryption(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                                    String[] identityVector, String delegateId, String[] identityVectorEnc) {
        try {
            PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identityVector);
            PairingKeySerParameter delegateKey = engine.delegate(publicKey, secretKey, delegateId);
            byte[] byteArrayDelegateKey = TestUtils.SerCipherParameter(delegateKey);
            CipherParameters anDelegateKey = TestUtils.deserCipherParameters(byteArrayDelegateKey);
            Assert.assertEquals(delegateKey, anDelegateKey);
            delegateKey = (PairingKeySerParameter)anDelegateKey;

            //Encryption and serialization
            Element message = pairing.getGT().newRandomElement().getImmutable();
            PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityVectorEnc, message);
            byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            Element anMessage = engine.decryption(publicKey, delegateKey, identityVectorEnc, ciphertext);
            Assert.assertEquals(message, anMessage);

            //Encapsulation and serialization
            PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, identityVectorEnc);
            byte[] sessionKey = encapsulationPair.getSessionKey();
            PairingCipherSerParameter header = encapsulationPair.getHeader();
            byte[] byteArrayHeader = TestUtils.SerCipherParameter(header);
            CipherParameters anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
            Assert.assertEquals(anHeader, anHeader);
            header = (PairingCipherSerParameter)anHeader;

            //Decapsulation
            byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identityVectorEnc, header);
            Assert.assertArrayEquals(sessionKey, anSessionKey);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid delegate decryption test failed, " +
                    "identity vector = " + Arrays.toString(identityVector) + ", " +
                    "delegate ident. = " + delegateId + ", " +
                    "iv encapsulation = " + Arrays.toString(identityVectorEnc));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void runAllTests(PairingParameters pairingParameters) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        try {
            // Setup and serialization
            PairingKeySerPair keyPair = engine.setup(pairingParameters, identityVector123.length);
            PairingKeySerParameter publicKey = keyPair.getPublic();
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            Assert.assertEquals(publicKey, anPublicKey);
            publicKey = (PairingKeySerParameter) anPublicKey;

            PairingKeySerParameter masterKey = keyPair.getPrivate();
            byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
            CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
            Assert.assertEquals(masterKey, anMasterKey);
            masterKey = (PairingKeySerParameter) anMasterKey;

            //test valid example
            System.out.println("Test valid examples");
            try_valid_decryption(pairing, publicKey, masterKey, identityVector1, identityVector12);
            try_valid_decryption(pairing, publicKey, masterKey, identityVector1, identityVector123);
            try_valid_decryption(pairing, publicKey, masterKey, identityVector12, identityVector123);
            try_valid_decryption(pairing, publicKey, masterKey, identityVector123, identityVector123);
            try_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector1, "ID_2", identityVector12);
            try_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector1, "ID_2", identityVector123);
            try_delegation_valid_decryption(pairing, publicKey, masterKey, identityVector12, "ID_3", identityVector123);

            //test valid example
            System.out.println("Test invalid examples");
            try_invalid_decryption(pairing, publicKey, masterKey, identityVector3, identityVector1);
            try_invalid_decryption(pairing, publicKey, masterKey, identityVector31, identityVector1);
            try_invalid_decryption(pairing, publicKey, masterKey, identityVector31, identityVector123);
            try_invalid_decryption(pairing, publicKey, masterKey, identityVector132, identityVector123);
            try_delegation_invalid_decryption(pairing, publicKey, masterKey, identityVector3, "ID_1", identityVector1);
            try_delegation_invalid_decryption(pairing, publicKey, masterKey, identityVector12, "ID_3", identityVector132);
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

    public void testHIBEBB04Engine() {
        this.engine = HIBEBB04Engine.getInstance();
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testHIBEBBG05Engine() {
        this.engine = HIBEBBG05Engine.getInstance();
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

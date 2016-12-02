package com.example.encryption.be;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.BEEngine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/3.
 *
 * BE engine JUnit test.
 */
public class BEEngineJUnitTest {
    private static final int maxNumUser = 8;
    private static final int index1_valid = 1;
    private static final int index8_valid = 8;
    private static final int index6_invalid = 6;
    private static final int index0_invalid = 0;
    private static final int index9_invalid = 9;

    private static final int[] indexSet1;
    private static final int[] indexSet2;
    private static final int[] indexSet3;

    static {
        indexSet1 = new int[]{1};
        indexSet2 = new int[] {1, 2, 5, 7, 8};
        indexSet3 = new int[]{1, 1, 5, 2, 2, 5, 8, 7, 7};
    }

    private BEEngine engine;

    public BEEngineJUnitTest(BEEngine engine) {
        this.engine = engine;
    }

    private void try_valid_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int index, int[] indexSet) {
        try {
            try_decapsulation(publicKey, masterKey, index, indexSet);
        } catch (Exception e) {
            System.out.println("Valid decapsulation test failed, " +
                    "index  = " + index + ", " +
                    "indexSet = " + Arrays.toString(indexSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_invalid_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int index, int[] indexSet) {
        try {
            try_decapsulation(publicKey, masterKey, index, indexSet);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (IllegalArgumentException e) {
            //correct if getting there, nothing to do
        }
        catch (Exception e) {
            System.out.println("Invalid decapsulation test failed, " +
                    "index  = " + index + ", " +
                    "indexSet = " + Arrays.toString(indexSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, int index, int[] indexSet)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, index);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (PairingKeySerParameter)anSecretKey;

        //Encryption and serialization
        PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, indexSet);
        byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getHeader();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, indexSet, ciphertext);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    public void runAllTests(PairingParameters pairingParameters) {
        try {
            // Setup and serialization
            PairingKeySerPair keyPair = engine.setup(pairingParameters, maxNumUser);
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
            try_valid_decapsulation(publicKey, masterKey, index1_valid, indexSet1);
            try_valid_decapsulation(publicKey, masterKey, index1_valid, indexSet2);
            try_valid_decapsulation(publicKey, masterKey, index8_valid, indexSet2);
            try_valid_decapsulation(publicKey, masterKey, index1_valid, indexSet3);
            try_valid_decapsulation(publicKey, masterKey, index8_valid, indexSet3);

            //test valid example
            System.out.println("Test invalid examples");
            try_invalid_decapsulation(publicKey, masterKey, index0_invalid, indexSet2);
            try_invalid_decapsulation(publicKey, masterKey, index6_invalid, indexSet2);
            try_invalid_decapsulation(publicKey, masterKey, index9_invalid, indexSet2);
            try_invalid_decapsulation(publicKey, masterKey, index0_invalid, indexSet3);
            try_invalid_decapsulation(publicKey, masterKey, index6_invalid, indexSet3);
            try_invalid_decapsulation(publicKey, masterKey, index9_invalid, indexSet3);
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

package com.example.encryption.ibbe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * IBBE engine test procedures. All instances should pass this unit test.
 */
public class IBBEEngineTest {
    private static final String identity_satisfied = "ID_0";
    private static final String identity_unsatisfied = "ID_9";

    private static final String[] identitySet1 = {"ID_0"};
    private static final String[] identitySet2 = {"ID_2", "ID_3", "ID_1", "ID_0"};
    private static final String[] identitySet3 = {"ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0"};
    private static final String[] identitySet4 = {"ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0", "ID_8"};

    private IBBEEngine engine;

    public IBBEEngineTest(IBBEEngine engine) {
        this.engine = engine;
    }

    private void test_valid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          String identity, String[] identitySet) {
        try {
            test_decapsulation(publicKey, masterKey, identity, identitySet);
        } catch (Exception e) {
            System.out.println("Valid decapsulation test failed, " +
                    "identity  = " + identity + ", " +
                    "id vector = " + Arrays.toString(identitySet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_invalid_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                            String identity, String[] identitySet) {
        try {
            test_decapsulation(publicKey, masterKey, identity, identitySet);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid decapsulation test failed, " +
                    "identity  = " + identity + ", " +
                    "id vector = " + Arrays.toString(identitySet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_decapsulation(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                    String identity, String[] identitySet)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identity);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (AsymmetricKeySerParameter)anSecretKey;

        //Encryption and serialization
        PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identitySet);
        byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getCiphertext();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identitySet, ciphertext);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    public void processTest(PairingParameters pairingParameters) {
        try {
            // Setup and serialization
            AsymmetricKeySerPair keyPair = engine.setup(pairingParameters, identitySet4.length);
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
            test_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet1);
            test_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet2);
            test_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet3);
            test_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet4);

            //test valid example
            System.out.println("Test invalid examples");
            test_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet1);
            test_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet2);
            test_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet3);
            test_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet4);
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

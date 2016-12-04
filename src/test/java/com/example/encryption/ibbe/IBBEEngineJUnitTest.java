package com.example.encryption.ibbe;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import cn.edu.buaa.crypto.encryption.ibbe.del07.IBBEDel07Engine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
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
public class IBBEEngineJUnitTest extends TestCase {
    private static final String identity_satisfied = "ID_0";
    private static final String identity_unsatisfied = "ID_9";

    private static final String[] identitySet1 = {"ID_0"};
    private static final String[] identitySet2 = {"ID_2", "ID_3", "ID_1", "ID_0"};
    private static final String[] identitySet3 = {"ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0"};
    private static final String[] identitySet4 = {"ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0", "ID_8"};

    private IBBEEngine engine;

    private void try_valid_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                          String identity, String[] identitySet) {
        try {
            try_decapsulation(publicKey, masterKey, identity, identitySet);
        } catch (Exception e) {
            System.out.println("Valid decapsulation test failed, " +
                    "identity  = " + identity + ", " +
                    "id vector = " + Arrays.toString(identitySet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_invalid_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                            String identity, String[] identitySet) {
        try {
            try_decapsulation(publicKey, masterKey, identity, identitySet);
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

    private void try_decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                    String identity, String[] identitySet)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identity);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (PairingKeySerParameter)anSecretKey;

        //Encryption and serialization
        PairingKeyEncapsulationSerPair keyEncapsulationSerPair = engine.encapsulation(publicKey, identitySet);
        byte[] sessionKey = keyEncapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = keyEncapsulationSerPair.getHeader();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, identitySet, ciphertext);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void runAllTests(PairingParameters pairingParameters) {
        try {
            // Setup and serialization
            PairingKeySerPair keyPair = engine.setup(pairingParameters, identitySet4.length);
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
            try_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet1);
            try_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet2);
            try_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet3);
            try_valid_decapsulation(publicKey, masterKey, identity_satisfied, identitySet4);

            //test valid example
            System.out.println("Test invalid examples");
            try_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet1);
            try_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet2);
            try_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet3);
            try_invalid_decapsulation(publicKey, masterKey, identity_unsatisfied, identitySet4);
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

    public void testIBBEDel07Engine() {
        this.engine = IBBEDel07Engine.getInstance();
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

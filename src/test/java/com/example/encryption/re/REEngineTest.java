package com.example.encryption.re;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.re.REEngine;
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
 * Created by Weiran Liu on 2016/4/4.
 *
 * Revocation encryption engine test.
 */
public class REEngineTest {
    private static final String identity = "ID";
    private static final String identityRevoke = "RevokeID";

    private static final String[] identityRevokeSet1 = {"ID_1", "RevokeID"};
    private static final String[] identityRevokeSet2 = {"RevokeID", "ID_1"};
    private static final String[] identityRevokeSet3 = {"ID_1", "ID_2", "ID_3", "ID_4", "RevokeID", "ID_5", "ID_6", "ID_7", "ID_8", "ID_9"};
    private static final String[] identityRevokeSet4 = {"ID_2", "ID_2", "ID_2", "ID_3", "RevokeID", "ID_5", "ID_5", "ID_5", "ID_5", "ID_9"};

    private REEngine engine;

    public REEngineTest(REEngine engine) {
        this.engine = engine;
    }

    private void test_valid_decryption(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                       String identity, String[] identityRevokeSet) {
        try {
            test_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet);
        } catch (Exception e) {
            System.out.println("Valid decryption test failed, " +
                    "identity for secret key  = " + identity + ", " +
                    "ciphertext revoke ID set = " + Arrays.toString(identityRevokeSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_invalid_decryption(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                            String identity, String[] identityRevokeSet) {
        try {
            test_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid decryption test failed, " +
                    "identity for secret key  = " + identity + ", " +
                    "ciphertext revoke ID set = " + Arrays.toString(identityRevokeSet));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_decryption(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                    String identity, String[] identityRevokeSet)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identity);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (AsymmetricKeySerParameter)anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identityRevokeSet, message);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        Element anMessage = engine.decryption(publicKey, secretKey, identityRevokeSet, ciphertext);
        Assert.assertEquals(message, anMessage);
    }

    public void processTest(PairingParameters pairingParameters) {
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
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
            test_valid_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet1);
            test_valid_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet2);
            test_valid_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet3);
            test_valid_decryption(pairing, publicKey, masterKey, identity, identityRevokeSet4);

            //test valid example
            System.out.println("Test invalid examples");
            test_invalid_decryption(pairing, publicKey, masterKey, identityRevoke, identityRevokeSet1);
            test_invalid_decryption(pairing, publicKey, masterKey, identityRevoke, identityRevokeSet2);
            test_invalid_decryption(pairing, publicKey, masterKey, identityRevoke, identityRevokeSet3);
            test_invalid_decryption(pairing, publicKey, masterKey, identityRevoke, identityRevokeSet4);
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

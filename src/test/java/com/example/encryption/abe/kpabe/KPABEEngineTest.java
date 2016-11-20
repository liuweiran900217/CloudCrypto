package com.example.encryption.abe.kpabe;

import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import com.example.TestUtils;
import com.example.access.AccessPolicyExamples;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * KP-ABE engine test.
 */
public class KPABEEngineTest {
    private KPABEEngine engine;

    public KPABEEngineTest(KPABEEngine engine) {
        this.engine = engine;
    }

    private void test_valid_access_policy(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          final String accessPolicyString, final String[] attributes) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            test_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_valid_access_policy(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            test_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_invalid_access_policy(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                            final String accessPolicyString, final String[] attributes) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            test_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (InvalidCipherTextException e) {
            //correct, expected exception, nothing to do.
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_invalid_access_policy(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                            final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            test_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (InvalidCipherTextException e) {
            //correct, expected exception, nothing to do.
        } catch (InvalidParameterException e) {
            //correct, expected exception, nothing to do.
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void test_access_policy(Pairing pairing, AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey,
                                          final int[][] accessPolicy, final String[] rhos, final String[] attributes)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        AsymmetricKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, accessPolicy, rhos);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (AsymmetricKeySerParameter)anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        PairingCipherSerParameter ciphertext = engine.encryption(publicKey, attributes, message);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        Element anMessage = engine.decryption(publicKey, secretKey, attributes, ciphertext);
        Assert.assertEquals(message, anMessage);
    }

    public void processTest(PairingParameters pairingParameters) {
        try {
            Pairing pairing = PairingFactory.getPairing(pairingParameters);
            // Setup and serialization
            AsymmetricKeySerPair keyPair = engine.setup(pairingParameters, 50);
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

            //test examples
            System.out.println("Test example 1");
            test_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_satisfied_1);
            test_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_satisfied_2);
            test_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_unsatisfied_1);

            //test example 2
            System.out.println("Test example 2");
            test_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_satisfied_1);
            test_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_satisfied_2);
            test_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_1);
            test_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_2);
            test_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_3);

            //test example 3
            System.out.println("Test example 3");
            test_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_satisfied_1);
            test_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_unsatisfied_1);
            test_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_unsatisfied_2);

            if (engine.isAccessControlEngineSupportThresholdGate()) {
                //test threshold example 1
                System.out.println("Test threshold example 1");
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied01);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied02);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied03);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied04);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied05);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied06);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied07);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied08);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied09);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied10);
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied11);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied01);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied02);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied03);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied04);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied05);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied06);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied07);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied08);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied09);

                //test threshold example 2
                System.out.println("Test threshold example 2");
                test_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_satisfied01);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied01);
                test_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied02);
            }
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

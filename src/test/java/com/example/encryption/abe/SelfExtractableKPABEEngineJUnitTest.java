package com.example.encryption.abe;

import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.KPABEGPSW06aEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.KPABEGPSW06bEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.KPABERW13Engine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.SelfExtractableKPABEEngine;
import com.example.TestUtils;
import com.example.access.AccessPolicyExamples;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.junit.Assert;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/4.
 *
 * Self-extractable KP-ABE engine unit test.
 */
public class SelfExtractableKPABEEngineJUnitTest extends TestCase {
    private SelfExtractableKPABEEngine engine;

    public void setEngine(SelfExtractableKPABEEngine engine) {
        this.engine = engine;
    }

    private void try_valid_access_policy(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         final String accessPolicyString, final String[] attributes) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            try_access_policy(publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_valid_access_policy(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            try_access_policy(publicKey, masterKey, accessPolicy, rhos, attributes);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_invalid_access_policy(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                           final String accessPolicyString, final String[] attributes) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            try_access_policy(publicKey, masterKey, accessPolicy, rhos, attributes);
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

    private void try_invalid_access_policy(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                           final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            try_access_policy(publicKey, masterKey, accessPolicy, rhos, attributes);
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

    private void try_access_policy(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                   final int[][] accessPolicy, final String[] rhos, final String[] attributes)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, accessPolicy, rhos);
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (PairingKeySerParameter)anSecretKey;

        //self KeyGen
        byte[] ek = engine.selfKeyGen();

        //Encapsulation and serialization
        PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, attributes, ek);
        byte[] sessionKey = encapsulationPair.getSessionKey();
        PairingCipherSerParameter header = encapsulationPair.getHeader();
        byte[] byteArrayHeader = TestUtils.SerCipherParameter(header);
        CipherParameters anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
        Assert.assertEquals(header, anHeader);
        header = (PairingCipherSerParameter)anHeader;

        //Decryption
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, attributes, header);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
        //Self decapsulation
        byte[] anSelfSessionKey = engine.selfDecapsulation(ek, header);
        Assert.assertArrayEquals(sessionKey, anSelfSessionKey);
    }

    public void runAllTests(PairingParameters pairingParameters) {
        try {
            // Setup and serialization
            PairingKeySerPair keyPair = engine.setup(pairingParameters, 50);
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

            //test examples
            System.out.println("Test example 1");
            try_valid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_satisfied_1);
            try_valid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_satisfied_2);
            try_invalid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_exampe_1_unsatisfied_1);

            //test example 2
            System.out.println("Test example 2");
            try_valid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_satisfied_1);
            try_valid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_satisfied_2);
            try_invalid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_1);
            try_invalid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_2);
            try_invalid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_exampe_2_unsatisfied_3);

            //test example 3
            System.out.println("Test example 3");
            try_valid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_satisfied_1);
            try_invalid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_unsatisfied_1);
            try_invalid_access_policy(
                    publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_exampe_3_unsatisfied_2);

            if (engine.isAccessControlEngineSupportThresholdGate()) {
                //test threshold example 1
                System.out.println("Test threshold example 1");
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied01);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied02);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied03);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied04);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied05);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied06);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied07);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied08);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied09);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied10);
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied11);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied01);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied02);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied03);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied04);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied05);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied06);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied07);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied08);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied09);

                //test threshold example 2
                System.out.println("Test threshold example 2");
                try_valid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_satisfied01);
                try_invalid_access_policy(
                        publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied01);
                try_invalid_access_policy(
                        publicKey, masterKey,
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

    public void testSEKPABEEngineBaseCase() {
        Digest digest = new SHA256Digest();
        KPABEEngine kpabeEngine = KPABERW13Engine.getInstance();
        BlockCipher blockCipher = new AESEngine();
        PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
        SelfExtractableKPABEEngine seKPABEEngine = new SelfExtractableKPABEEngine(kpabeEngine, pbeParametersGenerator, blockCipher, digest);
        SelfExtractableKPABEEngineJUnitTest engineJUnitTest = new SelfExtractableKPABEEngineJUnitTest();
        engineJUnitTest.setEngine(seKPABEEngine);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testSEKPABEEngineWithGPSW06a() {
        Digest digest = new SHA256Digest();
        KPABEEngine kpabeEngine = KPABEGPSW06aEngine.getInstance();
        BlockCipher blockCipher = new AESEngine();
        PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
        SelfExtractableKPABEEngine seKPABEEngine = new SelfExtractableKPABEEngine(kpabeEngine, pbeParametersGenerator, blockCipher, digest);
        SelfExtractableKPABEEngineJUnitTest engineJUnitTest = new SelfExtractableKPABEEngineJUnitTest();
        engineJUnitTest.setEngine(seKPABEEngine);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testSEKPABEEngineWithGPSW06b() {
        Digest digest = new SHA256Digest();
        KPABEEngine kpabeEngine = KPABEGPSW06bEngine.getInstance();
        BlockCipher blockCipher = new AESEngine();
        PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
        SelfExtractableKPABEEngine seKPABEEngine = new SelfExtractableKPABEEngine(kpabeEngine, pbeParametersGenerator, blockCipher, digest);
        SelfExtractableKPABEEngineJUnitTest engineJUnitTest = new SelfExtractableKPABEEngineJUnitTest();
        engineJUnitTest.setEngine(seKPABEEngine);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testSEKPABEEngineWithPKCS5S2() {
        Digest digest = new SHA256Digest();
        KPABEEngine kpabeEngine = KPABERW13Engine.getInstance();
        BlockCipher blockCipher = new AESEngine();
        PBEParametersGenerator pbeParametersGenerator = new PKCS5S2ParametersGenerator(digest);
        SelfExtractableKPABEEngine seKPABEEngine = new SelfExtractableKPABEEngine(kpabeEngine, pbeParametersGenerator, blockCipher, digest);
        SelfExtractableKPABEEngineJUnitTest engineJUnitTest = new SelfExtractableKPABEEngineJUnitTest();
        engineJUnitTest.setEngine(seKPABEEngine);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testSEKPABEEngineWithPKCS12() {
        Digest digest = new SHA256Digest();
        KPABEEngine kpabeEngine = KPABERW13Engine.getInstance();
        BlockCipher blockCipher = new AESEngine();
        PBEParametersGenerator pbeParametersGenerator = new PKCS12ParametersGenerator(digest);
        SelfExtractableKPABEEngine seKPABEEngine = new SelfExtractableKPABEEngine(kpabeEngine, pbeParametersGenerator, blockCipher, digest);
        SelfExtractableKPABEEngineJUnitTest engineJUnitTest = new SelfExtractableKPABEEngineJUnitTest();
        engineJUnitTest.setEngine(seKPABEEngine);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testSEKPABEEngineWithSHA512() {
        Digest digest = new SHA512Digest();
        KPABEEngine kpabeEngine = KPABERW13Engine.getInstance();
        BlockCipher blockCipher = new AESEngine();
        PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
        SelfExtractableKPABEEngine seKPABEEngine = new SelfExtractableKPABEEngine(kpabeEngine, pbeParametersGenerator, blockCipher, digest);
        SelfExtractableKPABEEngineJUnitTest engineJUnitTest = new SelfExtractableKPABEEngineJUnitTest();
        engineJUnitTest.setEngine(seKPABEEngine);
        engineJUnitTest.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

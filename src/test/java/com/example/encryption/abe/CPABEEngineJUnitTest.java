package com.example.encryption.abe;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.*;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.KR00bDigestHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bHasher;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyGenerationParameters;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bKeyPairGenerator;
import cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.DLogKR00bUniversalHasher;
import cn.edu.buaa.crypto.encryption.abe.cpabe.CPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.OOCPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.CPABEBSW07Engine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEReEncGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.OOCPABEHW14Engine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.CPABELLW14Engine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.OOCPABELLW16Engine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.CPABERW13Engine;
import com.example.TestUtils;
import com.example.access.AccessPolicyExamples;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.junit.Assert;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * CP-ABE engine test.
 */
public class CPABEEngineJUnitTest extends TestCase {
    private CPABEEngine engine;
    private CPABERW13Engine rw13Engine = CPABERW13Engine.getInstance();

    private void try_valid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         final String accessPolicyString, final String[] attributes) {
        try {
            System.out.println("accessPolicyString:" + accessPolicyString);
            System.out.println("attributes:" + Arrays.asList(attributes));
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            try_access_policy_ABPRE(pairing, publicKey, masterKey, accessPolicy, rhos, attributes, "gaga");
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_valid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            try_access_policy_ABPRE(pairing, publicKey, masterKey, accessPolicy, rhos, attributes, "gaga");
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_invalid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                           final String accessPolicyString, final String[] attributes) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            try_access_policy_ABPRE(pairing, publicKey, masterKey, accessPolicy, rhos, attributes, "gaga");
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

    private void try_invalid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                           final int[][] accessPolicy, final String[] rhos, final String[] attributes) {
        try {
            try_access_policy_ABPRE(pairing, publicKey, masterKey, accessPolicy, rhos, attributes,  "gaga");
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

    private void try_access_policy_ABPRE(Pairing pairing, PairingKeySerParameter publicKey,
                                         PairingKeySerParameter masterKey, final int[][] accessPolicy,
                                         final String[] rhos, final String[] attributes, final String ID)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = rw13Engine.keyGen(publicKey, masterKey, attributes);
        // 将产生的私钥序列化
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        // ？
        secretKey = (PairingKeySerParameter)anSecretKey;

        //IDKeyGen and serialization
        PairingKeySerParameter IDSecretKey = rw13Engine.IDKeyGen(publicKey, masterKey, ID);
        // 将产生的ID私钥序列化
        byte[] byteArrayIDSecretKey = TestUtils.SerCipherParameter(IDSecretKey);
        CipherParameters anIDSecretKey = TestUtils.deserCipherParameters(byteArrayIDSecretKey);
        Assert.assertEquals(IDSecretKey, anIDSecretKey);
        IDSecretKey = (PairingKeySerParameter)anIDSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        PairingCipherSerParameter ciphertext = rw13Engine.encryption(publicKey, accessPolicy, rhos, message);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //reKeyGen and serialization
        PairingKeySerParameter reEncKey = rw13Engine.reKeyGen(publicKey, secretKey, ID);
        // 将产生的私钥序列化
        byte[] byteArrayReEncKey = TestUtils.SerCipherParameter(reEncKey);
        CipherParameters anReEncKey = TestUtils.deserCipherParameters(byteArrayReEncKey);
        Assert.assertEquals(reEncKey, anReEncKey);
        reEncKey = (PairingKeySerParameter)anReEncKey;

        //Decryption
        Element anMessage = rw13Engine.decryption(publicKey, secretKey, accessPolicy, rhos, ciphertext);
        Assert.assertEquals(message, anMessage);


        //reEncryption and serialization
        PairingCipherSerParameter reEncCiphertext = rw13Engine
                .reEncryption(publicKey, reEncKey, ciphertext, accessPolicy, rhos);
        byte[] byteArrayReEncCiphertext = TestUtils.SerCipherParameter(reEncCiphertext);
        CipherParameters anReEncCiphertext = TestUtils.deserCipherParameters(byteArrayReEncCiphertext);
        Assert.assertEquals(reEncCiphertext, anReEncCiphertext);
        reEncCiphertext = (PairingCipherSerParameter)anReEncCiphertext;

        //reDecryption
        Element anReDecMessage = rw13Engine.reDecryption(publicKey, IDSecretKey, reEncCiphertext);
        Assert.assertEquals(message, anReDecMessage);

        //Encapsulation and serialization
        PairingKeyEncapsulationSerPair encapsulationPair = rw13Engine.encapsulation(publicKey, accessPolicy, rhos);
        byte[] sessionKey = encapsulationPair.getSessionKey();
        PairingCipherSerParameter header = encapsulationPair.getHeader();
        byte[] byteArrayHeader = TestUtils.SerCipherParameter(header);
        CipherParameters anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
        Assert.assertEquals(header, anHeader);
        header = (PairingCipherSerParameter)anHeader;

        //Decapsulation
        byte[] anSessionKey = rw13Engine.decapsulation(publicKey, secretKey, accessPolicy, rhos, header);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void try_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                   final int[][] accessPolicy, final String[] rhos, final String[] attributes)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, attributes);
        // 将产生的私钥序列化
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        // ？
        secretKey = (PairingKeySerParameter)anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        System.out.println("pt:" + message);
        PairingCipherSerParameter ciphertext = engine.encryption(publicKey, accessPolicy, rhos, message);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        Element anMessage = engine.decryption(publicKey, secretKey, accessPolicy, rhos, ciphertext);
        System.out.println("dec(ct)::" + anMessage);
        Assert.assertEquals(message, anMessage);

        //Encapsulation and serialization
        PairingKeyEncapsulationSerPair encapsulationPair = engine.encapsulation(publicKey, accessPolicy, rhos);
        byte[] sessionKey = encapsulationPair.getSessionKey();
        PairingCipherSerParameter header = encapsulationPair.getHeader();
        byte[] byteArrayHeader = TestUtils.SerCipherParameter(header);
        CipherParameters anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
        Assert.assertEquals(header, anHeader);
        header = (PairingCipherSerParameter)anHeader;

        //Decapsulation
        byte[] anSessionKey = engine.decapsulation(publicKey, secretKey, accessPolicy, rhos, header);
        Assert.assertArrayEquals(sessionKey, anSessionKey);

        //try online/offline mechanism
        if (this.engine instanceof OOCPABEEngine) {
            OOCPABEEngine ooEngine = (OOCPABEEngine)engine;
            //offline encryption and serialization
            PairingCipherSerParameter intermediate = ooEngine.offlineEncryption(publicKey, rhos.length);
            byte[] byteArrayIntermediate = TestUtils.SerCipherParameter(intermediate);
            CipherParameters anIntermediate = TestUtils.deserCipherParameters(byteArrayIntermediate);
            Assert.assertEquals(intermediate, anIntermediate);
            intermediate = (PairingCipherSerParameter)anIntermediate;

            //Encryption and serialization
            ciphertext = ooEngine.encryption(publicKey, intermediate, accessPolicy, rhos, message);
            byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
            anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            Assert.assertEquals(ciphertext, anCiphertext);
            ciphertext = (PairingCipherSerParameter)anCiphertext;

            //Decryption
            anMessage = engine.decryption(publicKey, secretKey, accessPolicy, rhos, ciphertext);
            Assert.assertEquals(message, anMessage);

            //Encapsulation and serialization
            encapsulationPair = ooEngine.encapsulation(publicKey, intermediate, accessPolicy, rhos);
            sessionKey = encapsulationPair.getSessionKey();
            header = encapsulationPair.getHeader();
            byteArrayHeader = TestUtils.SerCipherParameter(header);
            anHeader = TestUtils.deserCipherParameters(byteArrayHeader);
            Assert.assertEquals(header, anHeader);
            header = (PairingCipherSerParameter)anHeader;

            //Decapsulation
            anSessionKey = engine.decapsulation(publicKey, secretKey, accessPolicy, rhos, header);
            Assert.assertArrayEquals(sessionKey, anSessionKey);
        }
    }

    public void runAllTests(PairingParameters pairingParameters) {
        try {
            Pairing pairing = PairingFactory.getPairing(pairingParameters);
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
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_example_1_satisfied_1);
            try_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_example_1_satisfied_2);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_1,
                    AccessPolicyExamples.access_policy_example_1_unsatisfied_1);

            //test example 2
            System.out.println("Test example 2");
            try_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_example_2_satisfied_1);
            try_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_example_2_satisfied_2);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_example_2_unsatisfied_1);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_example_2_unsatisfied_2);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_2,
                    AccessPolicyExamples.access_policy_example_2_unsatisfied_3);

            //test example 3
            System.out.println("Test example 3");
            try_valid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_example_3_satisfied_1);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_example_3_unsatisfied_1);
            try_invalid_access_policy(
                    pairing, publicKey, masterKey,
                    AccessPolicyExamples.access_policy_example_3,
                    AccessPolicyExamples.access_policy_example_3_unsatisfied_2);

            if (engine.isAccessControlEngineSupportThresholdGate()) {
                //test threshold example 1
                System.out.println("Test threshold example 1");
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied01);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied02);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied03);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied04);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied05);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied06);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied07);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied08);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied09);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied10);
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_satisfied11);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied01);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied02);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied03);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied04);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied05);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied06);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied07);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied08);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_1_tree,
                        AccessPolicyExamples.access_policy_threshold_example_1_rho,
                        AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied09);

                //test threshold example 2
                System.out.println("Test threshold example 2");
                try_valid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_satisfied01);
                try_invalid_access_policy(
                        pairing, publicKey, masterKey,
                        AccessPolicyExamples.access_policy_threshold_example_2_tree,
                        AccessPolicyExamples.access_policy_threshold_example_2_rho,
                        AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied01);
                try_invalid_access_policy(
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

    public void testCPABEBSW07Engine() {
        this.engine = CPABEBSW07Engine.getInstance();
        System.out.println("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
        engine.setAccessControlEngine(AccessTreeEngine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

        System.out.println("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
        engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testCPABERW13Engine() {
        this.engine = CPABERW13Engine.getInstance();
        System.out.println("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
        engine.setAccessControlEngine(AccessTreeEngine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

        System.out.println("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
        engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testCPAB_PRERW13Engine() {
        this.engine = CPABERW13Engine.getInstance();
        System.out.println("test rw13 CP-AB-PRE schemes:");
        System.out.println("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
        engine.setAccessControlEngine(AccessTreeEngine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

        System.out.println("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
        engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testCPABELLW14Engine() {
        this.engine = CPABELLW14Engine.getInstance();
        System.out.println("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
        engine.setAccessControlEngine(AccessTreeEngine.getInstance());

        ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bHasher(), new SHA256Digest());
        AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
        KeyGenerationParameters keyGenerationParameters = new DLogKR00bKeyGenerationParameters(new SecureRandom(),
                SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);
        ((CPABELLW14Engine)this.engine).setChameleonHasher(chameleonHasher, chKeyPairGenerator, keyGenerationParameters);
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

        System.out.println("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
        engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

    public void testCPABEHW14Engine() {
        this.engine = OOCPABEHW14Engine.getInstance();
        System.out.println("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
        engine.setAccessControlEngine(AccessTreeEngine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));

        System.out.println("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
        engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }

//    public void testCPABELLW16Engine() {
//        this.engine = OOCPABELLW16Engine.getInstance();
//        System.out.println("Test " + engine.getEngineName() + " using " + AccessTreeEngine.SCHEME_NAME);
//        engine.setAccessControlEngine(AccessTreeEngine.getInstance());
//
//        ChameleonHasher chameleonHasher = new KR00bDigestHasher(new DLogKR00bUniversalHasher(new SHA256Digest()), new SHA256Digest());
//        AsymmetricKeySerPairGenerator chKeyPairGenerator = new DLogKR00bKeyPairGenerator();
//        KeyGenerationParameters keyGenerationParameters = new DLogKR00bKeyGenerationParameters(new SecureRandom(),
//                SecurePrimeSerParameter.RFC3526_1536BIT_MODP_GROUP);
//        ((OOCPABELLW16Engine)this.engine).setChameleonHasher(chameleonHasher, chKeyPairGenerator, keyGenerationParameters);
//        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
//
//        System.out.println("Test " + engine.getEngineName() + " using " + LSSSLW10Engine.SCHEME_NAME);
//        engine.setAccessControlEngine(LSSSLW10Engine.getInstance());
//        runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
//    }
}

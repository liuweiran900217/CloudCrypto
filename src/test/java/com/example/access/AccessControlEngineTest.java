package com.example.access;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.utils.PairingUtils;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.junit.Assert;

import java.io.IOException;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/20.
 *
 * Access control engine test.
 */
public class AccessControlEngineTest {
    private AccessControlEngine accessControlEngine;
    private Pairing pairing;

    public AccessControlEngineTest(AccessControlEngine accessControlEngine) {
        this.accessControlEngine = accessControlEngine;
        PropertiesParameters parameters = PairingUtils.GenerateTypeAParameters(160, 512);
        this.pairing = PairingFactory.getPairing(parameters);
    }



    public void testAccessPolicy() {
        //test satisfied access control
        if (this.accessControlEngine.isSupportThresholdGate()) {
            test_valid_access_policy(1,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied01);
            test_valid_access_policy(2,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied02);
            test_valid_access_policy(3,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied03);
            test_valid_access_policy(4,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied04);
            test_valid_access_policy(5,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied05);
            test_valid_access_policy(6,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied06);
            test_valid_access_policy(7,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied07);
            test_valid_access_policy(8,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied08);
            test_valid_access_policy(9,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied09);
            test_valid_access_policy(10,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied10);
            test_valid_access_policy(11,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_satisfied11);
            test_valid_access_policy(20,
                    AccessPolicyExamples.access_policy_threshold_example_2_tree,
                    AccessPolicyExamples.access_policy_threshold_example_2_rho,
                    AccessPolicyExamples.access_policy_threshold_example_2_satisfied01);

            //test unsatisfied access control
            test_invalid_access_policy(1,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied01);
            test_invalid_access_policy(2,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied02);
            test_invalid_access_policy(3,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied03);
            test_invalid_access_policy(4,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied04);
            test_invalid_access_policy(5,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied05);
            test_invalid_access_policy(6,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied06);
            test_invalid_access_policy(7,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied07);
            test_invalid_access_policy(8,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied08);
            test_invalid_access_policy(9,
                    AccessPolicyExamples.access_policy_threshold_example_1_tree,
                    AccessPolicyExamples.access_policy_threshold_example_1_rho,
                    AccessPolicyExamples.access_policy_threshold_example_1_unsatisfied09);
            test_invalid_access_policy(20,
                    AccessPolicyExamples.access_policy_threshold_example_2_tree,
                    AccessPolicyExamples.access_policy_threshold_example_2_rho,
                    AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied01);
            test_invalid_access_policy(21,
                    AccessPolicyExamples.access_policy_threshold_example_2_tree,
                    AccessPolicyExamples.access_policy_threshold_example_2_rho,
                    AccessPolicyExamples.access_policy_threshold_example_2_unsatisfied02);
        }

        test_valid_access_policy(31,
                AccessPolicyExamples.access_policy_example_1,
                AccessPolicyExamples.access_policy_exampe_1_satisfied_1);
        test_valid_access_policy(32,
                AccessPolicyExamples.access_policy_example_1,
                AccessPolicyExamples.access_policy_exampe_1_satisfied_2);
        test_valid_access_policy(41,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_exampe_2_satisfied_1);
        test_valid_access_policy(42,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_exampe_2_satisfied_2);
        test_valid_access_policy(51,
                AccessPolicyExamples.access_policy_example_3,
                AccessPolicyExamples.access_policy_exampe_3_satisfied_1);

        test_invalid_access_policy(31,
                AccessPolicyExamples.access_policy_example_1,
                AccessPolicyExamples.access_policy_exampe_1_unsatisfied_1);
        test_invalid_access_policy(41,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_exampe_2_unsatisfied_1);
        test_invalid_access_policy(42,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_exampe_2_unsatisfied_2);
        test_invalid_access_policy(53,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_exampe_2_unsatisfied_3);
        test_invalid_access_policy(51,
                AccessPolicyExamples.access_policy_example_3,
                AccessPolicyExamples.access_policy_exampe_3_unsatisfied_1);
        test_invalid_access_policy(52,
                AccessPolicyExamples.access_policy_example_3,
                AccessPolicyExamples.access_policy_exampe_3_unsatisfied_2);
    }

    private void test_valid_access_policy(int testIndex, final String accessPolicyString, final String[] attributeSet) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
//            for (int i = 0; i < accessPolicy.length; i++) {
//                for (int j = 0 ; j < accessPolicy[i].length; j++) {
//                    System.out.print(accessPolicy[i][j] + ", ");
//                }
//                System.out.println();
//            }
//            System.out.println();
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            test_valid_access_policy(testIndex, accessPolicy, rhos, attributeSet);
        } catch (PolicySyntaxException e) {
            System.out.println("Access Policy with Combined Gate Satisfied Test " + testIndex + ", Error for parsing...");
            e.printStackTrace();
        }
    }

    private void test_invalid_access_policy(int testIndex, final String accessPolicyString, final String[] attributeSet) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
//            for (int i = 0; i < accessPolicy.length; i++) {
//                for (int j = 0 ; j < accessPolicy[i].length; j++) {
//                    System.out.print(accessPolicy[i][j] + ", ");
//                }
//                System.out.println();
//            }
//            System.out.println();
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            test_invalid_access_policy(testIndex, accessPolicy, rhos, attributeSet);
        } catch (PolicySyntaxException e) {
            System.out.println("Access Policy with Combined Gate Satisfied Test " + testIndex + ", Error for parsing...");
            e.printStackTrace();
        }
    }


    private void test_valid_access_policy(int testIndex, final int[][] accessPolicy, final String[] rhos, final String[] attributeSet) {
        try {
            //Access Policy Generation
            AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);
            //SecretSharing
            Element secret = pairing.getZr().newRandomElement().getImmutable();
//        System.out.println("Generated Secret s = " + secret);
            Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, secret, accessControlParameter);

            //test access parameter serialization
            byte[] byteArrayAccessParameter = TestUtils.SerCipherParameter(accessControlParameter);
            CipherParameters anAccessControlParameter = TestUtils.deserCipherParameters(byteArrayAccessParameter);
            Assert.assertEquals(accessControlParameter, anAccessControlParameter);

            //Secret Reconstruction
            accessControlParameter = (AccessControlParameter)anAccessControlParameter;
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, attributeSet, accessControlParameter);
            Element reconstructedSecret = pairing.getZr().newZeroElement().getImmutable();
            for (String eachAttribute : attributeSet) {
                if (omegaElementsMap.containsKey(eachAttribute)) {
                    reconstructedSecret = reconstructedSecret.add(lambdaElementsMap.get(eachAttribute).mulZn(omegaElementsMap.get(eachAttribute))).getImmutable();
                }
            }
//        System.out.println("Reconstruct Secret s = " + reconstructedSecret);
            if (!reconstructedSecret.equals(secret)) {
                System.out.println("Access Policy with Combined Gate Satisfied Test " + testIndex + ", Reconstructed Secret Wrong...");
                System.exit(0);
            }
            System.out.println("Access Policy with Combined Gate Satisfied Test " + testIndex + " Passed.");
        } catch (UnsatisfiedAccessControlException e) {
            System.out.println("Access Policy with Combined Gate Satisfied Test " + testIndex + ", Error for getting Exceptions...");
            e.printStackTrace();
            System.exit(0);
        } catch (IOException e) {
            System.out.println("Access Policy with Combined Gate Satisfied Test " + testIndex + ", Error for getting Exceptions...");
            e.printStackTrace();
            System.exit(0);
        } catch (ClassNotFoundException e) {
            System.out.println("Access Policy with Combined Gate Satisfied Test " + testIndex + ", Error for getting Exceptions...");
            e.printStackTrace();
            System.exit(0);
        }
    }

    private void test_invalid_access_policy(int testIndex, final int[][] accessPolicy, final String[] rhos, final String[] attributeSet) {
        try {
            //Access Policy Generation
            AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);
            //SecretSharing
            Element secret = pairing.getZr().newRandomElement().getImmutable();
//        System.out.println("Generated Secret s = " + secret);
            Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, secret, accessControlParameter);
            //Secret Reconstruction
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, attributeSet, accessControlParameter);
            Element reconstructedSecret = pairing.getZr().newZeroElement().getImmutable();
            for (String eachAttribute : attributeSet) {
                if (omegaElementsMap.containsKey(eachAttribute)) {
                    reconstructedSecret = reconstructedSecret.add(lambdaElementsMap.get(eachAttribute).mulZn(omegaElementsMap.get(eachAttribute))).getImmutable();
                }
            }
            System.out.println("Access Policy with Combined Gate Unsatisfied Test " + testIndex + ", Error for not getting Exceptions...");
            System.exit(0);
        } catch (UnsatisfiedAccessControlException e) {
            System.out.println("Access Policy with Combined Gate Unsatisfied Test " + testIndex + " Passed.");
        }
    }
}

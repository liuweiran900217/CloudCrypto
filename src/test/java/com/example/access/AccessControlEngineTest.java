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

    private static final String access_policy_example_1 = "school:pku and professor and (academy:software or academy:computer)";
    private static final String[] access_policy_exampe_1_satisfied_1 = new String[] {"school:pku", "professor", "academy:software"};
    private static final String[] access_policy_exampe_1_satisfied_2 = new String[] {"school:pku", "professor", "academy:software", "academy:computer"};
    private static final String[] access_policy_exampe_1_unsatisfied_1 = new String[] {"professor", "academy:software", "academy:computer"};

    private static final String access_policy_example_2 = "((A and B and C) and (D or E or F) and (G and H and (I or J or K or L)))";
    private static final String[] access_policy_exampe_2_satisfied_1 = new String[] {"A", "B", "C", "E", "G", "H", "K"};
    private static final String[] access_policy_exampe_2_satisfied_2 = new String[] {"A", "B", "C", "F", "E", "G", "H", "I", "J", "K", "L"};
    private static final String[] access_policy_exampe_2_unsatisfied_1 = new String[] {"A", "B", "C", "G", "H", "K"};
    private static final String[] access_policy_exampe_2_unsatisfied_2 = new String[] {"A", "B", "C", "E", "G", "K"};
    private static final String[] access_policy_exampe_2_unsatisfied_3 = new String[] {"A", "B", "C", "D", "G", "H"};

    private static final String access_policy_example_3 =
            "A_00 and A_01 and A_02 and A_03 and A_04 and A_05 and A_06 and A_07 and A_08 and A_09 and " +
            "A_10 and A_11 and A_12 and A_13 and A_14 and A_15 and A_16 and A_17 and A_18 and A_19 and " +
            "A_20 and A_21 and A_22 and A_23 and A_24 and A_25 and A_26 and A_27 and A_28 and A_29 and " +
            "A_30 and A_31 and A_32 and A_33 and A_34 and A_35 and A_36 and A_37 and A_38 and A_39 and " +
            "A_40 and A_41 and A_42 and A_43 and A_44 and A_45 and A_46 and A_47 and A_48 and A_49";
    private static final String[] access_policy_exampe_3_satisfied_1 = new String[] {
            "A_00", "A_01", "A_02", "A_03", "A_04", "A_05", "A_06", "A_07", "A_08", "A_09",
            "A_10", "A_11", "A_12", "A_13", "A_14", "A_15", "A_16", "A_17", "A_18", "A_19",
            "A_20", "A_21", "A_22", "A_23", "A_24", "A_25", "A_26", "A_27", "A_28", "A_29",
            "A_30", "A_31", "A_32", "A_33", "A_34", "A_35", "A_36", "A_37", "A_38", "A_39",
            "A_40", "A_41", "A_42", "A_43", "A_44", "A_45", "A_46", "A_47", "A_48", "A_49",
    };
    private static final String[] access_policy_exampe_3_unsatisfied_1 = new String[] {
            "A_00", "A_01", "A_02", "A_03", "A_04", "A_05", "A_06", "A_07", "A_08", "A_09",
            "A_10", "A_11", "A_12", "A_13", "A_14", "A_15", "A_16", "A_17", "A_18", "A_19",
            "A_20", "A_21", "A_22", "A_23", "A_24", "A_25", "A_26", "A_27", "A_28", "A_29",
            "A_30", "A_31", "A_32", "A_33", "A_34", "A_35", "A_36", "A_37", "A_38", "A_39",
            "A_40", "A_41", "A_42", "A_43", "A_44", "A_45", "A_46", "A_47", "A_48",
    };
    private static final String[] access_policy_exampe_3_unsatisfied_2 = new String[] {
            "A_04", "A_05", "A_06", "A_07", "A_08", "A_09",
            "A_10", "A_11", "A_12", "A_13", "A_14", "A_15", "A_16", "A_17", "A_18", "A_19",
            "A_20", "A_21", "A_22", "A_23", "A_24", "A_25", "A_26", "A_27", "A_28", "A_29",
            "A_30", "A_31", "A_32", "A_33", "A_34",          "A_37", "A_38", "A_39",
            "A_40", "A_41", "A_42", "A_43", "A_44", "A_45", "A_46", "A_47", "A_48", "A_49",
    };

    private static final int[][] access_policy_paper_example_tree = {
            {3, 2, 1, 2, 3},
            {3, 2, -1, -2, -3},
            {3, 2, -4, -5, -6},
            {3, 2, -7, -8, 4},
            {4, 3, -9, -10, -11, -12},
    };
    private static final String[] access_policy_paper_example_rho = new String[] {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10","11",
    };
    private static final String[] access_policy_paper_example_satisfied01 = new String[] {
            "0", "1", "3", "4",
    };
    private static final String[] access_policy_paper_example_satisfied02 = new String[] {
            "0", "1", "6", "7",
    };
    private static final String[] access_policy_paper_example_satisfied03 = new String[] {
            "0", "1", "6", "8", "9", "10",
    };
    private static final String[] access_policy_paper_example_satisfied04 = new String[] {
            "1", "2", "7", "8", "10", "11",
    };
    private static final String[] access_policy_paper_example_satisfied05 = new String[] {
            "3", "5", "6", "7",
    };
    private static final String[] access_policy_paper_example_satisfied06 = new String[] {
            "3", "5", "7", "8", "10", "11",
    };
    private static final String[] access_policy_paper_example_satisfied07 = new String[] {
            "4", "5", "7", "9", "10", "11",
    };
    private static final String[] access_policy_paper_example_satisfied08 = new String[] {
            "0", "1", "2", "3", "4",
    };
    private static final String[] access_policy_paper_example_satisfied09 = new String[] {
            "3", "4", "5", "6", "8", "9", "10", "11",
    };
    private static final String[] access_policy_paper_example_satisfied10 = new String[] {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10","11",
    };
    private static final String[] access_policy_paper_example_satisfied11 = new String[] {
            "11", "10", "8", "9", "4", "5", "6", "3", "2", "0", "1", "7",
    };
    private static final String[] access_policy_paper_example_unsatisfied01 = new String[] {
            "0", "3", "6", "8", "9",
    };
    private static final String[] access_policy_paper_example_unsatisfied02 = new String[] {
            "0", "3", "6", "7",
    };
    private static final String[] access_policy_paper_example_unsatisfied03 = new String[] {
            "0", "4", "8", "9", "10",
    };
    private static final String[] access_policy_paper_example_unsatisfied04 = new String[] {
            "1", "2", "5", "6", "10",
    };
    private static final String[] access_policy_paper_example_unsatisfied05 = new String[] {
            "3", "5", "2", "7", "10", "11"
    };
    private static final String[] access_policy_paper_example_unsatisfied06 = new String[] {
            "3", "5", "7", "8", "10", "10"
    };
    private static final String[] access_policy_paper_example_unsatisfied07 = new String[] {
            "3", "4", "4", "8", "9", "10", "10"
    };
    private static final String[] access_policy_paper_example_unsatisfied08 = new String[] {
            "0", "1", "2", "3", "-5",
    };
    private static final String[] access_policy_paper_example_unsatisfied09 = new String[] {
            "5", "8", "9", "10", "14", "20",
    };

    private static final int[][] access_policy_combine_tree = {
            {2,2,1,2}, //the root node 0 is a 2of2 threshold and its children are nodes 1 and 2 (at rows 1 and 2) <br>
            {2,2,3,4}, //node 1 is a 1of2 threshold and its children are nodes 3 and 4 <br>
            {4,3,-7,-8,-9,-10}, //node 2 note that -5 here correponds to index of attribute E in the alphabet<br>
            {2,2,-2,5}, //node 3 <br>
            {3,2,-4,-5,-6}, //node 4 <br>
            {2,1,-1,-3} //node 5 <br>
    };
    private static final String[] access_policy_combine_rho = new String[] {
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
    };
    private static final String[] access_policy_combine_satisfied = new String[] {
            "B", "C", "E", "F", "G", "I", "J",
    };
    private static final String[] access_policy_combine_unsatisfied1 = new String[] {
            "A", "C", "D", "F", "G", "I", "J",
    };
    private static final String[] access_policy_combine_unsatisfied2 = new String[] {
            "B", "C", "E", "F", "H", "I",
    };

    public AccessControlEngineTest(AccessControlEngine accessControlEngine) {
        this.accessControlEngine = accessControlEngine;
        PropertiesParameters parameters = PairingUtils.GenerateTypeAParameters(160, 512);
        this.pairing = PairingFactory.getPairing(parameters);
    }



    public void testAccessPolicy() {
        //test satisfied access control
        if (this.accessControlEngine.isSupportThresholdGate()) {
            test_valid_access_policy(1, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied01);
            test_valid_access_policy(2, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied02);
            test_valid_access_policy(3, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied03);
            test_valid_access_policy(4, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied04);
            test_valid_access_policy(5, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied05);
            test_valid_access_policy(6, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied06);
            test_valid_access_policy(7, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied07);
            test_valid_access_policy(8, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied08);
            test_valid_access_policy(9, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied09);
            test_valid_access_policy(10, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied10);
            test_valid_access_policy(11, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_satisfied11);
            test_valid_access_policy(20, access_policy_combine_tree, access_policy_combine_rho, access_policy_combine_satisfied);

            //test unsatisfied access control
            test_invalid_access_policy(1, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_unsatisfied01);
            test_invalid_access_policy(2, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_unsatisfied02);
            test_invalid_access_policy(3, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_unsatisfied03);
            test_invalid_access_policy(4, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_unsatisfied04);
            test_invalid_access_policy(5, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_unsatisfied05);
            test_invalid_access_policy(6, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_unsatisfied06);
            test_invalid_access_policy(7, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_unsatisfied07);
            test_invalid_access_policy(8, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_unsatisfied08);
            test_invalid_access_policy(9, access_policy_paper_example_tree, access_policy_paper_example_rho, access_policy_paper_example_unsatisfied09);
            test_invalid_access_policy(20, access_policy_combine_tree, access_policy_combine_rho, access_policy_combine_unsatisfied1);
            test_invalid_access_policy(21, access_policy_combine_tree, access_policy_combine_rho, access_policy_combine_unsatisfied2);
        }

        test_valid_access_policy(31, access_policy_example_1, access_policy_exampe_1_satisfied_1);
        test_valid_access_policy(32, access_policy_example_1, access_policy_exampe_1_satisfied_2);
        test_valid_access_policy(41, access_policy_example_2, access_policy_exampe_2_satisfied_1);
        test_valid_access_policy(42, access_policy_example_2, access_policy_exampe_2_satisfied_2);
        test_valid_access_policy(51, access_policy_example_3, access_policy_exampe_3_satisfied_1);

        test_invalid_access_policy(31, access_policy_example_1, access_policy_exampe_1_unsatisfied_1);
        test_invalid_access_policy(41, access_policy_example_2, access_policy_exampe_2_unsatisfied_1);
        test_invalid_access_policy(42, access_policy_example_2, access_policy_exampe_2_unsatisfied_2);
        test_invalid_access_policy(53, access_policy_example_2, access_policy_exampe_2_unsatisfied_3);
        test_invalid_access_policy(51, access_policy_example_3, access_policy_exampe_3_unsatisfied_1);
        test_invalid_access_policy(52, access_policy_example_3, access_policy_exampe_3_unsatisfied_2);
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

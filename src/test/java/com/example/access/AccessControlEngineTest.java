package com.example.access;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/20.
 */
public class AccessControlEngineTest {
    private AccessControlEngine accessControlEngine;
    private Pairing pairing;

    private static int[][] access_policy_50_and_gate_tree = {
        {50, 50, -1, -2, -3, -4, -5, -6, -7, -8, -9,-10,
                -11,-12,-13,-14,-15,-16,-17,-18,-19,-20,
                -21,-22,-23,-24,-25,-26,-27,-28,-29,-30,
                -31,-32,-33,-34,-35,-36,-37,-38,-39,-40,
                -41,-42,-43,-44,-45,-46,-47,-48,-49,-50,
        }};
    private static String[] access_policy_50_and_gate_rho = new String[] {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
            "10","11","12","13","14","15","16","17","18","19",
            "20","21","22","23","24","25","26","27","28","29",
            "30","31","32","33","34","35","36","37","38","39",
            "40","41","42","43","44","45","46","47","48","49",
    };
    private static String[] access_policy_50_and_gate_satisfied = new String[] {
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
            "10","11","12","13","14","15","16","17","18","19",
            "20","21","22","23","24","25","26","27","28","29",
            "30","31","32","33","34","35","36","37","38","39",
            "40","41","42","43","44","45","46","47","48","49",
    };
    private static String[] access_policy_50_and_gate_unsatisfied = new String[] {
            "3", "4", "5", "6", "7", "8", "9",
            "10","11","12","13","14","15","16","17","18","19",
            "20","21","22","23","24","25","26","27","28","29",
            "30","31","32","33","34","35","36","37","38","39",
            "40","41","42","43","44","45","46","47","48","49",
    };

    private static int[][] access_policy_combine_tree = {
            {2,2,1,2}, //the root node 0 is a 2of2 threshold and its children are nodes 1 and 2 (at rows 1 and 2) <br>
            {2,2,3,4}, //node 1 is a 1of2 threshold and its children are nodes 3 and 4 <br>
            {4,3,-7,-8,-9,-10}, //node 2 note that -5 here correponds to index of attribute E in the alphabet<br>
            {2,2,-2,5}, //node 3 <br>
            {3,2,-4,-5,-6}, //node 4 <br>
            {2,1,-1,-3} //node 5 <br>
    };
    private static String[] access_policy_combine_rho = new String[] {
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
    };
    private static String[] access_policy_combine_satisfied = new String[] {
            "B", "C", "E", "F", "G", "I", "J",
    };
    private static String[] access_policy_combine_unsatisfied1 = new String[] {
            "A", "C", "D", "F", "G", "I", "J",
    };
    private static String[] access_policy_combine_unsatisfied2 = new String[] {
            "B", "C", "E", "F", "H", "I",
    };

    public AccessControlEngineTest(AccessControlEngine accessControlEngine) {
        this.accessControlEngine = accessControlEngine;
        TypeACurveGenerator pg = new TypeACurveGenerator(160, 512);
        PairingParameters typeAParams = pg.generate();
        this.pairing = PairingFactory.getPairing(typeAParams);
    }

    public void testAccessPolicy() {
        //test satisfied access control
        try {
            if (!test_one_access_policy(access_policy_50_and_gate_tree, access_policy_50_and_gate_rho, access_policy_50_and_gate_satisfied)) {
                System.out.println("Access Policy with 50 AND Gate Satisfied Test, Reconstructed Secret Wrong...");
                System.exit(0);
            } else {
                System.out.println("Access Policy with 50 AND Gate Satisfied Test Passed.");
            }
            if(!test_one_access_policy(access_policy_combine_tree, access_policy_combine_rho, access_policy_combine_satisfied)) {
                System.out.println("Access Policy with Combined Gate Satisfied Test, Reconstructed Secret Wrong...");
                System.exit(0);
            } else {
                System.out.println("Access Policy with Combined Gate Satisfied Test Passed.");
            }
        } catch (UnsatisfiedAccessControlException e) {
            System.out.println("Error for getting Exceptions...");
            e.printStackTrace();
            System.exit(0);
        }
        //test unsatisfied access control
        try {
            test_one_access_policy(access_policy_50_and_gate_tree, access_policy_50_and_gate_rho, access_policy_50_and_gate_unsatisfied);
            System.out.println("Access Policy with 50 AND Gate Unsatisfied Test, Error for not getting Exceptions...");
            System.exit(0);
        } catch (UnsatisfiedAccessControlException e) {
            System.out.println("Access Policy with 50 AND Gate Unsatisfied Test Passed.");
        }
        try {
            test_one_access_policy(access_policy_combine_tree, access_policy_combine_rho, access_policy_combine_unsatisfied1);
            System.out.println("Access Policy with Combined Gate Unsatisfied Test 1, Error for not getting Exceptions...");
            System.exit(0);
        } catch (UnsatisfiedAccessControlException e) {
            System.out.println("Access Policy with Combined Gate Unsatisfied Test 1 Passed.");
        }
        try {
            test_one_access_policy(access_policy_combine_tree, access_policy_combine_rho, access_policy_combine_unsatisfied2);
            System.out.println("Access Policy with Combined Gate Unsatisfied Test 2, Error for not getting Exceptions...");
            System.exit(0);
        } catch (UnsatisfiedAccessControlException e) {
            System.out.println("Access Policy with Combined Gate Unsatisfied Test 2 Passed.");
        }
    }

    private boolean test_one_access_policy(final int[][] accessPolicy, final String[] rhos, final String[] attributeSet) throws UnsatisfiedAccessControlException {
        //Access Policy Generation
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);
        //SecretSharing
        Element secret = pairing.getZr().newRandomElement().getImmutable();
//        System.out.println("Generated Secret s = " + secret);
        Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, secret, accessControlParameter);
        //Secret Reconstruction
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, attributeSet, accessControlParameter);
        Element reconstructedSecret = pairing.getZr().newZeroElement().getImmutable();
        for (int i = 0; i < attributeSet.length; i++) {
            if (omegaElementsMap.containsKey(attributeSet[i])) {
                reconstructedSecret = reconstructedSecret.add(lambdaElementsMap.get(attributeSet[i]).mulZn(omegaElementsMap.get(attributeSet[i]))).getImmutable();
            }
        }
//        System.out.println("Reconstruct Secret s = " + reconstructedSecret);
        return reconstructedSecret.equals(secret);
    }
}

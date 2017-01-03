package com.example.encryption.abe;

import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.KPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.OOKPABEEngine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.OOKPABEHW14Engine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.KPABELLW14Engine;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.OOKPABELLW16Engine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.utils.Timer;
import com.example.TestUtils;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/4.
 *
 * Generic KP-ABE performance test.
 */
public class KPABEPerformanceTest extends TestCase {
    private String pairingParameterPath;
    //file path for performance test result
    private static final String default_path = "benchmarks/encryption/kpabe/";
    //test round
    private int test_round;
    //the maximal number of role index is chosen
    private int maximal_attributes;
    //setup time
    private double timeSetup;

    //attributeSets
    private String[][] attributeSets;
    //secret key generation time
    private double[] timeKeyGen;

    //access policy
    private String[] accessPolicies;
    //key encapsulation time
    private double[] timeEncapsulation;
    //key encryption time
    private double[] timeEncryption;
    //online offline
    private double[] timeOfflineEncryption;
    private double[] timeOnlineEncryption;
    private double[] timeOnlineEncapsulation;

    //decapsulation time
    private double[] timeDecapsulation;
    private double[] timeDecryption;
    //online offline
    private double[] timeOnlineDecapsulation;
    private double[] timeOnlineDecryption;

    private KPABEEngine engine;

    private Out out;

    private void init() {
        this.attributeSets = new String[maximal_attributes][];
        this.timeKeyGen = new double[maximal_attributes];
        this.accessPolicies = new String[maximal_attributes];
        this.timeEncapsulation = new double[maximal_attributes];
        this.timeEncryption = new double[maximal_attributes];
        this.timeOfflineEncryption = new double[maximal_attributes];
        this.timeOnlineEncryption = new double[maximal_attributes];
        this.timeOnlineEncapsulation = new double[maximal_attributes];
        this.timeDecapsulation = new double[maximal_attributes];
        this.timeDecryption = new double[maximal_attributes];
        this.timeOnlineDecapsulation = new double[maximal_attributes];
        this.timeOnlineDecryption = new double[maximal_attributes];

        //create attributeSets
        for (int i = 0; i < maximal_attributes; i++){
            this.attributeSets[i] = new String[i+1];
        }
        for (int i = 0; i < maximal_attributes; i++){
            for (int j = 0; j <= i; j++){
                this.attributeSets[i][j] = "A_" + (j);
            }
        }

//        for (int i = 0; i < this.attributeSets.length; i++) {
//            System.out.print("i = " + i + ": ");
//            for (int j = 0; j < this.attributeSets[i].length; j++) {
//                System.out.print(this.attributeSets[i][j] + " ");
//            }
//            System.out.println();
//        }

        //create access policies for encapsulation / encryption
        for (int i = 0; i < maximal_attributes; i++) {
            this.accessPolicies[i] = "";
        }
        for (int i = 0; i < maximal_attributes; i++){
            for (int j = 0; j < i; j++){
                this.accessPolicies[i] += "A_" + (j) + " AND ";
            }
            this.accessPolicies[i] += "A_" + (i);
        }
//        for (int i = 0; i < this.accessPolicies.length; i++) {
//            System.out.println(this.accessPolicies[i]);
//        }
    }

    private void runPerformanceTest() {
        out = new Out(default_path + engine.getEngineName());
        out.println("Test KP-ABE engine: " + engine.getEngineName());
        out.println("All test rounds: " + this.test_round);

        for (int i = 0; i < test_round; i++) {
            System.out.println("Test round: " + (i+1));
            out.println("Test round: " + (i+1));
            run_one_round();
        }
        out.println();
        out.println("Final performance test:");
        //write results to the file
        //write setup time
        out.print("Setup : ");
        out.print("\t" + this.timeSetup / test_round);
        out.println();

        //write KeyGen
        out.print("KeyGen: ");
        for (int i = 0; i < maximal_attributes; i++) {
            out.print("\t" + this.timeKeyGen[i] / test_round);
        }
        out.println();

        //write encapsulation
        out.print("Encapsulation: ");
        for (int i = 0; i < maximal_attributes; i++) {
            out.print("\t" + this.timeEncapsulation[i] / test_round);
        }
        out.println();

        //write encryption
        out.print("Encryption: ");
        for (int i = 0; i < maximal_attributes; i++) {
            out.print("\t" + this.timeEncryption[i] / test_round);
        }
        out.println();

        //write decryption
        out.print("Decryption: ");
        for (int i = 0; i < maximal_attributes; i++) {
            out.print("\t" + this.timeDecryption[i] / test_round);
        }
        out.println();

        //write decapsulation
        out.print("Decapsulation: ");
        for (int i = 0; i < maximal_attributes; i++) {
            out.print("\t" + this.timeDecapsulation[i] / test_round);
        }
        out.println();

        if (this.engine instanceof OOKPABEEngine) {
            //write offline encryption
            out.print("Offline Encryption: ");
            for (int i = 0; i < maximal_attributes; i++) {
                out.print("\t" + this.timeOfflineEncryption[i] / test_round);
            }
            out.println();

            //write online encapsulation
            out.print("Online Encapsulation: ");
            for (int i = 0; i < maximal_attributes; i++) {
                out.print("\t" + this.timeOnlineEncapsulation[i] / test_round);
            }
            out.println();

            //write online encryption
            out.print("Online Encryption: ");
            for (int i = 0; i < maximal_attributes; i++) {
                out.print("\t" + this.timeOnlineEncryption[i] / test_round);
            }
            out.println();

            //write online decryption
            out.print("Online Decryption: ");
            for (int i = 0; i < maximal_attributes; i++) {
                out.print("\t" + this.timeOnlineDecryption[i] / test_round);
            }
            out.println();

            //write online decapsulation
            out.print("Online Decapsulation: ");
            for (int i = 0; i < maximal_attributes; i++) {
                out.print("\t" + this.timeOnlineDecapsulation[i] / test_round);
            }
            out.println();
        }
    }

    private void run_one_round() {
        try {
            PairingParameters pairingParameters = PairingFactory.getPairingParameters(pairingParameterPath);
            Pairing pairing = PairingFactory.getPairing(pairingParameters);

            double temperTime;
            Timer timer = new Timer(maximal_attributes);
            //test setup performance
            System.out.print("Setup; ");
            out.print("Setup : ");
            timer.start(0);
            PairingKeySerPair keyPair = engine.setup(pairingParameters, maximal_attributes);
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeSetup += temperTime;
            out.println();
            System.out.println();

            PairingKeySerParameter publicKey = keyPair.getPublic();
            PairingKeySerParameter masterKey = keyPair.getPrivate();

            out.print("KeyGen: ");
            //test secret key generation performance
            PairingKeySerParameter[] secretKeys = new PairingKeySerParameter[maximal_attributes];
            for (int i = 0; i < maximal_attributes; i++) {
                System.out.print("KeyGen " + i + "; ");
                timer.start(i);
                secretKeys[i] = engine.keyGen(publicKey, masterKey, accessPolicies[i]);
                temperTime = timer.stop(i);
                out.print("\t" + temperTime);
                this.timeKeyGen[i] += temperTime;
            }
            out.println();
            System.out.println();

            out.print("Encryption: ");
            //test encryption performance
            PairingCipherSerParameter[] ciphertexts = new PairingCipherSerParameter[maximal_attributes];
            for (int i = 0; i < maximal_attributes; i++) {
                Element message = pairing.getGT().newRandomElement().getImmutable();
                System.out.print("Encryption " + i + "; ");
                timer.start(i);
                ciphertexts[i] = engine.encryption(publicKey, attributeSets[i], message);
                temperTime = timer.stop(i);
                out.print("\t" + temperTime);
                this.timeEncryption[i] += temperTime;
            }
            out.println();
            System.out.println();

            out.print("Encapsulation: ");
            //test encryption performance
            PairingCipherSerParameter[] headers = new PairingCipherSerParameter[maximal_attributes];
            for (int i = 0; i < maximal_attributes; i++) {
                System.out.print("Encapsulation " + i + "; ");
                timer.start(i);
                headers[i] = engine.encapsulation(publicKey, attributeSets[i]).getHeader();
                temperTime = timer.stop(i);
                out.print("\t" + temperTime);
                this.timeEncapsulation[i] += temperTime;
            }
            out.println();
            System.out.println();

            //test decryption performance
            out.print("Decryption; ");
            for (int i = 0; i < maximal_attributes; i++) {
                System.out.print("Decryption " + i + "; ");
                timer.start(i);
                engine.decryption(publicKey, secretKeys[i], attributeSets[i], ciphertexts[i]);
                temperTime = timer.stop(i);
                out.print("\t" + temperTime);
                this.timeDecryption[i] += temperTime;
            }
            out.println();
            System.out.println();

            out.print("Decapsulation: ");
            //test decapsulation performance
            for (int i = 0; i < maximal_attributes; i++) {
                System.out.print("Decapsulation " + i + "; ");
                timer.start(i);
                engine.decapsulation(publicKey, secretKeys[i], attributeSets[i], headers[i]);
                temperTime = timer.stop(i);
                out.print("\t" + temperTime);
                this.timeDecapsulation[i] += temperTime;
            }
            out.println();
            System.out.println();

            if (this.engine instanceof OOKPABEEngine) {
                OOKPABEEngine ooEngine = (OOKPABEEngine)this.engine;

                out.print("Offline Encryption: ");
                //test offline encryption performance
                PairingCipherSerParameter[] intermediates = new PairingCipherSerParameter[maximal_attributes];
                for (int i = 0; i < maximal_attributes; i++) {
                    System.out.print("Offline Encryption " + i + "; ");
                    timer.start(i);
                    intermediates[i] = ooEngine.offlineEncryption(publicKey, attributeSets[i].length);
                    temperTime = timer.stop(i);
                    out.print("\t" + temperTime);
                    this.timeOfflineEncryption[i] += temperTime;
                }
                out.println();
                System.out.println();

                out.print("Online Encryption: ");
                //test online encryption performance
                PairingCipherSerParameter[] onlineCiphertexts = new PairingCipherSerParameter[maximal_attributes];
                for (int i = 0; i < maximal_attributes; i++) {
                    Element message = pairing.getGT().newRandomElement().getImmutable();
                    System.out.print("Encryption " + i + "; ");
                    timer.start(i);
                    onlineCiphertexts[i] = ooEngine.encryption(publicKey, intermediates[i], attributeSets[i], message);
                    temperTime = timer.stop(i);
                    out.print("\t" + temperTime);
                    this.timeOnlineEncryption[i] += temperTime;
                }
                out.println();
                System.out.println();

                out.print("Online Encapsulation: ");
                //test encryption performance
                PairingCipherSerParameter[] onlineHeaders = new PairingCipherSerParameter[maximal_attributes];
                for (int i = 0; i < maximal_attributes; i++) {
                    System.out.print("Online Encapsulation " + i + "; ");
                    timer.start(i);
                    onlineHeaders[i] = ooEngine.encapsulation(publicKey, intermediates[i], attributeSets[i]).getHeader();
                    temperTime = timer.stop(i);
                    out.print("\t" + temperTime);
                    this.timeOnlineEncapsulation[i] += temperTime;
                }
                out.println();
                System.out.println();

                //test decryption performance
                out.print("Online Decryption; ");
                for (int i = 0; i < maximal_attributes; i++) {
                    System.out.print("Online Decryption " + i + "; ");
                    timer.start(i);
                    engine.decryption(publicKey, secretKeys[i], attributeSets[i], onlineCiphertexts[i]);
                    temperTime = timer.stop(i);
                    out.print("\t" + temperTime);
                    this.timeOnlineDecryption[i] += temperTime;
                }
                out.println();
                System.out.println();

                out.print("Online Decapsulation: ");
                //test decapsulation performance
                for (int i = 0; i < maximal_attributes; i++) {
                    System.out.print("Online Decapsulation " + i + "; ");
                    timer.start(i);
                    engine.decapsulation(publicKey, secretKeys[i], attributeSets[i], onlineHeaders[i]);
                    temperTime = timer.stop(i);
                    out.print("\t" + temperTime);
                    this.timeOnlineDecapsulation[i] += temperTime;
                }
                out.println();
                System.out.println();
            }
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        } catch (PolicySyntaxException e) {
            e.printStackTrace();
        }
    }

//    public void testRW13Performance() {
//        KPABEPerformanceTest performanceTest = new KPABEPerformanceTest();
////        performanceTest.maximal_attributes = 10;
////        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256;
////        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
//        performanceTest.maximal_attributes = 50;
//        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
//        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
//        performanceTest.engine = KPABERW13Engine.getInstance();
//        performanceTest.init();
//        performanceTest.runPerformanceTest();
//    }
//
//    public void testGPSW06bPerformance() {
//        KPABEPerformanceTest performanceTest = new KPABEPerformanceTest();
////        performanceTest.maximal_attributes = 10;
////        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256;
////        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
//        performanceTest.maximal_attributes = 50;
//        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
//        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
//        performanceTest.engine = KPABEGPSW06bEngine.getInstance();
//        performanceTest.init();
//        performanceTest.runPerformanceTest();
//    }

    public void testLLW14Performance() {
        KPABEPerformanceTest performanceTest = new KPABEPerformanceTest();
//        performanceTest.maximal_attributes = 10;
//        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256;
//        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
        performanceTest.maximal_attributes = 50;
        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        performanceTest.engine = KPABELLW14Engine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }

    public void testHW14Performance() {
        KPABEPerformanceTest performanceTest = new KPABEPerformanceTest();
//        performanceTest.maximal_attributes = 10;
//        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256;
//        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
        performanceTest.maximal_attributes = 50;
        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        performanceTest.engine = OOKPABEHW14Engine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }

    public void testLLW16Performance() {
        KPABEPerformanceTest performanceTest = new KPABEPerformanceTest();
//        performanceTest.maximal_attributes = 10;
//        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256;
//        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
        performanceTest.maximal_attributes = 50;
        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        performanceTest.engine = OOKPABELLW16Engine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }
}

package com.example.encryption.hibbe;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.HIBBELLW16aEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.HIBBELLW16bEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.HIBBELLW17Engine;
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
 * Created by Weiran Liu on 2016/11/7.
 *
 * HIBBE scheme performance test.
 */
public class HIBBEPerformanceTest extends TestCase {
    private String pairingParameterPath;
    //file path for performance test result
    private static final String default_path = "benchmarks/encryption/hibbe/";
    private int test_round;
    //the maximal depth of roles is chosen according to the full version of our paper.
    private int maximal_depth;
    //the maximal number of role index is chosen
    private int maximal_users;
    //setup time
    private double timeSetep;

    //identity vectors
    private String[][] identityVectors;
    //secret key generation time
    private double[] timeKeyGen;

    //secret key delegation time
    private double[] timeKeyDele;

    //identity vector sets for key encapsulation
    private String[][] encapsulationIdentityVectorSets;

    private double[] timeEncapsulation;
    private double[] timeEncryption;
    private double[][] timeDecapsulation;
    private double[][] timeDecryption;

    private HIBBEEngine engine;

    private Out out;

    public void init() {
        identityVectors = new String[maximal_depth][maximal_users];
        timeKeyGen = new double[maximal_depth];
        timeKeyDele = new double[maximal_depth];
        encapsulationIdentityVectorSets = new String[maximal_users][maximal_users];
        timeEncapsulation = new double[maximal_users];
        timeEncryption = new double[maximal_users];
        timeDecapsulation = new double[maximal_depth][maximal_users];
        timeDecryption = new double[maximal_depth][maximal_users];

        //create identity vectors
        for (int i = 0; i < maximal_depth; i++){
            for (int j = 0; j <= i; j++){
                this.identityVectors[i][j] = "Identity_" + (j);
            }
        }
//        for (int i = 0; i < this.identityVectors.length; i++) {
//            out.print("i = " + i + ": ");
//            for (int j = 0; j < this.identityVectors[i].length; j++) {
//                out.print(this.identityVectors[i][j] + " ");
//            }
//            out.println();
//        }

        //create identity vector sets for key encapsulation
        for (int i = 0; i < maximal_users; i++){
            for (int j = 0; j <= i; j++){
                this.encapsulationIdentityVectorSets[i][j] = "Identity_" + (j);
            }
        }
//        for (int i = 0; i < this.encapsulationIdentityVectorSets.length; i++) {
//            out.print("i = " + i + ": ");
//            for (int j = 0; j < this.encapsulationIdentityVectorSets[i].length; j++) {
//                out.print(this.encapsulationIdentityVectorSets[i][j] + " ");
//            }
//            out.println();
//        }
    }

    public void runPerformanceTest() {
        out = new Out(default_path + engine.getEngineName());
        out.println("Test HIBBE engine: " + engine.getEngineName());
        out.println("All test rounds: " + this.test_round);

        for (int i = 0; i < test_round; i++) {
            System.out.println("Test round: " + (i+1));
            out.println("Test round: " + (i+1));
            run_one_round();
        }
        //write results to the file
        //write setup time
        out.print("Setup : ");
        out.print("\t" + this.timeSetep / test_round);
        out.println();

        //write KeyGen
        out.print("KeyGen: ");
        for (int i = 0; i < maximal_depth; i++) {
            out.print("\t" + this.timeKeyGen[i] / test_round);
        }
        out.println();

        //write KeyDele
        out.print("Delegate: ");
        for (int i = 0; i < maximal_depth - 1; i++) {
            out.print("\t" + this.timeKeyDele[i + 1] / test_round);
        }
        out.println();

        //write encapsulation
        out.print("Encapsulation: ");
        for (int i = 0; i < maximal_users; i++) {
            out.print("\t" + this.timeEncapsulation[i] / test_round);
        }
        out.println();

        //write encryption
        out.print("Encryption: ");
        for (int i = 0; i < maximal_users; i++) {
            out.print("\t" + this.timeEncryption[i] / test_round);
        }
        out.println();

        //write decapsulation
        for (int i = 0; i < maximal_depth; i++) {
            out.print("Decapsulation " + i + ": ");
            for (int j = i; j < maximal_users; j++) {
                out.print("\t" + this.timeDecapsulation[i][j] / test_round);
            }
            out.println();
        }
        out.println();

        //write decryption
        for (int i = 0; i < maximal_depth; i++) {
            out.print("Decryption " + i + ": ");
            for (int j = i; j < maximal_users; j++) {
                out.print("\t" + this.timeDecryption[i][j] / test_round);
            }
            out.println();
        }
        out.println();
    }

    private void run_one_round() {
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(pairingParameterPath);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);

        double temperTime;
        Timer timer = new Timer(maximal_users);
        //test setup performance
        System.out.print("Setup; ");
        out.print("Setup : ");
        timer.start(0);
        PairingKeySerPair keyPair = engine.setup(pairingParameters, maximal_users);
        temperTime = timer.stop(0);
        out.print("\t" + temperTime);
        this.timeSetep += temperTime;
        out.println();

        PairingKeySerParameter publicKey = keyPair.getPublic();
        PairingKeySerParameter masterKey = keyPair.getPrivate();

        out.print("KeyGen: ");
        //test secret key generation performance
        PairingKeySerParameter[] secretKeys = new PairingKeySerParameter[maximal_depth];
        for (int i = 0; i < maximal_depth; i++) {
            System.out.print("KeyGen " + i + "; ");
            timer.start(i);
            secretKeys[i] = engine.keyGen(publicKey, masterKey, identityVectors[i]);
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeKeyGen[i] += temperTime;
        }
        out.println();
        System.out.println();

        out.print("Delegate: ");
        //test secret key delegation performance
        PairingKeySerParameter[] delegateKeys = new PairingKeySerParameter[maximal_depth];
        for (int i = 0; i < maximal_depth - 1; i++) {
            System.out.print("Delegate " + i + "; ");
            timer.start(i + 1);
            delegateKeys[i + 1] = engine.delegate(publicKey, secretKeys[i], i + 1, "Delegate");
            temperTime = timer.stop(i + 1);
            out.print("\t" + temperTime);
            this.timeKeyDele[i + 1] += temperTime;
        }
        out.println();
        System.out.println();

        out.print("Encapsulation: ");
        //test encryption performance
        PairingCipherSerParameter[] headers = new PairingCipherSerParameter[maximal_users];
        for (int i = 0; i < maximal_users; i++) {
            System.out.print("Encapsulation " + i + "; ");
            timer.start(i);
            headers[i] = engine.encapsulation(publicKey, encapsulationIdentityVectorSets[i]).getHeader();
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeEncapsulation[i] += temperTime;
        }
        out.println();
        System.out.println();

        out.print("Encryption: ");
        //test encryption performance
        PairingCipherSerParameter[] ciphertexts = new PairingCipherSerParameter[maximal_users];
        for (int i = 0; i < maximal_users; i++) {
            System.out.print("Encryption " + i + "; ");
            Element message = pairing.getGT().newRandomElement().getImmutable();
            timer.start(i);
            ciphertexts[i] = engine.encryption(publicKey, encapsulationIdentityVectorSets[i], message);
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeEncryption[i] += temperTime;
        }
        out.println();
        System.out.println();

        //test decapsulation performance
        for (int i = 0; i < maximal_depth; i++) {
            System.out.print("Decapsulation " + i + "; ");
            out.print("Decapsulation " + i + ": ");
            for (int j = i; j < maximal_users; j++) {
                try {
                    timer.start(i);
                    engine.decapsulation(publicKey, secretKeys[i], encapsulationIdentityVectorSets[j], headers[j]);
                    temperTime = timer.stop(i);
                    out.print("\t" + temperTime);
                    this.timeDecapsulation[i][j] += temperTime;
                } catch (InvalidCipherTextException e) {
                    e.printStackTrace();
                    System.exit(0);
                }
            }
            out.println();
        }
        out.println();
        System.out.println();

        //test decryption performance
        for (int i = 0; i < maximal_depth; i++) {
            System.out.print("Decryption " + i + "; ");
            out.print("Decryption " + i + ": ");
            for (int j = i; j < maximal_users; j++) {
                try {
                    timer.start(i);
                    engine.decryption(publicKey, secretKeys[i], encapsulationIdentityVectorSets[j], ciphertexts[j]);
                    temperTime = timer.stop(i);
                    out.print("\t" + temperTime);
                    this.timeDecryption[i][j] += temperTime;
                } catch (InvalidCipherTextException e) {
                    e.printStackTrace();
                    System.exit(0);
                }
            }
            out.println();
        }
        out.println();
        System.out.println();
    }

    public void testLLW14Performance() {
        HIBBEPerformanceTest performanceTest = new HIBBEPerformanceTest();
        performanceTest.maximal_users = 10;
        performanceTest.maximal_depth = 2;
        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128;
        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
//        performanceTest.maximal_users = 100;
//        performanceTest.maximal_depth = 10;
//        performanceTest.pairingParameterPath = PairingUtils.PATH_a1_3_512;
//        performanceTest.test_round = TestUtils.DEFAULT_COMPOSITE_ORDER_TEST_ROUND;
        performanceTest.engine = HIBBELLW14Engine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }

    public void testLLW16aPerformance() {
        HIBBEPerformanceTest performanceTest = new HIBBEPerformanceTest();
        performanceTest.maximal_users = 10;
        performanceTest.maximal_depth = 2;
        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256;
        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
//        performanceTest.maximal_users = 100;
//        performanceTest.maximal_depth = 10;
//        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
//        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        performanceTest.engine = HIBBELLW16aEngine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }

    public void testLLW16bPerformance() {
        HIBBEPerformanceTest performanceTest = new HIBBEPerformanceTest();
        performanceTest.maximal_users = 10;
        performanceTest.maximal_depth = 2;
        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256;
        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
//        performanceTest.maximal_users = 100;
//        performanceTest.maximal_depth = 10;
//        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
//        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        performanceTest.engine = HIBBELLW16bEngine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }

    public void testLLW17Performance() {
        HIBBEPerformanceTest performanceTest = new HIBBEPerformanceTest();
        performanceTest.maximal_users = 10;
        performanceTest.maximal_depth = 2;
        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128;
        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
//        performanceTest.maximal_users = 100;
//        performanceTest.maximal_depth = 10;
//        performanceTest.pairingParameterPath = PairingUtils.PATH_a1_3_512;
//        performanceTest.test_round = TestUtils.DEFAULT_COMPOSITE_ORDER_TEST_ROUND;
        performanceTest.engine = HIBBELLW17Engine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }
}
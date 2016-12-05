package com.example.encryption.ibbe;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import cn.edu.buaa.crypto.encryption.ibbe.del07.IBBEDel07Engine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.utils.Timer;
import com.example.TestUtils;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/5.
 *
 * Generic IBBE performance test.
 */
public class IBBEPerformanceTest extends TestCase {
    private String pairingParameterPath;
    //file path for performance test result
    private static final String default_path = "benchmarks/encryption/ibbe/";
    //test round
    private int test_round;
    //the maximal number of role index is chosen
    private int maximal_users;
    //setup time
    private double timeSetup;

    //indexes
    private String[] identities;
    //secret key generation time
    private double[] timeKeyGen;

    //index sets
    private String[][] identitySets;
    //key encapsulation time
    private double[] timeEncapsulation;

    //decapsulation time
    private double[] timeDecapsulation;

    private IBBEEngine engine;

    private Out out;

    private void init() {
        this.identities = new String[maximal_users];
        this.timeKeyGen = new double[maximal_users];
        this.identitySets = new String[maximal_users][];
        this.timeEncapsulation = new double[maximal_users];
        this.timeDecapsulation = new double[maximal_users];

        //create identitySets
        for (int i = 0; i < maximal_users; i++){
            this.identitySets[i] = new String[i+1];
        }
        for (int i = 0; i < maximal_users; i++){
            for (int j = 0; j <= i; j++){
                this.identitySets[i][j] = "ID_" + (j);
            }
        }

//        for (int i = 0; i < this.identitySets.length; i++) {
//            System.out.print("i = " + i + ": ");
//            System.out.print(Arrays.toString(identitySets[i]));
//            System.out.println();
//        }

        //create indexes
        for (int i = 0; i < maximal_users; i++) {
            this.identities[i] = "ID_" + (i);
        }

//        for (String identity : this.identities) {
//            System.out.println(identity);
//        }
    }

    private void runPerformanceTest() {
        out = new Out(default_path + engine.getEngineName());
        out.println("Test IBBE engine: " + engine.getEngineName());
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
        for (int i = 0; i < maximal_users; i++) {
            out.print("\t" + this.timeKeyGen[i] / test_round);
        }
        out.println();

        //write encapsulation
        out.print("Encapsulation: ");
        for (int i = 0; i < maximal_users; i++) {
            out.print("\t" + this.timeEncapsulation[i] / test_round);
        }
        out.println();

        //write decapsulation
        out.print("Decapsulation: ");
        for (int i = 0; i < maximal_users; i++) {
            out.print("\t" + this.timeDecapsulation[i] / test_round);
        }
        out.println();
    }

    private void run_one_round() {
        try {
            PairingParameters pairingParameters = PairingFactory.getPairingParameters(pairingParameterPath);

            double temperTime;
            Timer timer = new Timer(maximal_users);
            //test setup performance
            System.out.print("Setup; ");
            out.print("Setup : ");
            timer.start(0);
            PairingKeySerPair keyPair = engine.setup(pairingParameters, maximal_users);
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeSetup += temperTime;
            out.println();
            System.out.println();

            PairingKeySerParameter publicKey = keyPair.getPublic();
            PairingKeySerParameter masterKey = keyPair.getPrivate();

            out.print("KeyGen: ");
            //test secret key generation performance
            PairingKeySerParameter[] secretKeys = new PairingKeySerParameter[maximal_users];
            for (int i = 0; i < maximal_users; i++) {
                System.out.print("KeyGen " + i + "; ");
                timer.start(i);
                secretKeys[i] = engine.keyGen(publicKey, masterKey, identities[i]);
                temperTime = timer.stop(i);
                out.print("\t" + temperTime);
                this.timeKeyGen[i] += temperTime;
            }
            out.println();
            System.out.println();

            out.print("Encapsulation: ");
            //test encryption performance
            PairingCipherSerParameter[] headers = new PairingCipherSerParameter[maximal_users];
            for (int i = 0; i < maximal_users; i++) {
                System.out.print("Encapsulation " + i + "; ");
                timer.start(i);
                headers[i] = engine.encapsulation(publicKey, identitySets[i]).getHeader();
                temperTime = timer.stop(i);
                out.print("\t" + temperTime);
                this.timeEncapsulation[i] += temperTime;
            }
            out.println();
            System.out.println();

            out.print("Decapsulation: ");
            //test decapsulation performance
            for (int i = 0; i < maximal_users; i++) {
                System.out.print("Decapsulation " + i + "; ");
                timer.start(i);
                engine.decapsulation(publicKey, secretKeys[i], identitySets[i], headers[i]);
                temperTime = timer.stop(i);
                out.print("\t" + temperTime);
                this.timeDecapsulation[i] += temperTime;
            }
            out.println();
            System.out.println();
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }

    public void testDel07Performance() {
        IBBEPerformanceTest performanceTest = new IBBEPerformanceTest();
//        performanceTest.maximal_users = 10;
//        performanceTest.pairingParameterPath = TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256;
//        performanceTest.test_round = TestUtils.DEFAULT_SIMU_TEST_ROUND;
        performanceTest.maximal_users = 50;
        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        performanceTest.engine = IBBEDel07Engine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }
}

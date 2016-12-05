package com.example.encryption.ibe;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.IBEBF01aEngine;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.IBEGen06aEngine;
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
 * Created by Weiran Liu on 2016/12/5.
 *
 * Generic IBE performance test.
 */
public class IBEPerformanceTest extends TestCase {
    private String pairingParameterPath;
    //file path for performance test result
    private static final String default_path = "benchmarks/encryption/ibe/";
    //test round
    private int test_round;
    //setup time
    private double timeSetup;
    //identity
    private String identity;
    //secret key generation time
    private double timeKeyGen;

    //key encapsulation time
    private double timeEncapsulation;
    private double timeEncryption;

    //decapsulation time
    private double timeDecapsulation;
    private double timeDecryption;

    private IBEEngine engine;

    private Out out;

    private void init() {
        this.identity = "ID";
    }

    private void runPerformanceTest() {
        out = new Out(default_path + engine.getEngineName());
        out.println("Test IBE engine: " + engine.getEngineName());
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
        out.print("\t" + this.timeKeyGen / test_round);
        out.println();

        //write encapsulation
        out.print("Encapsulation: ");
        out.print("\t" + this.timeEncapsulation / test_round);
        out.println();

        //write encrption
        out.print("Encryption: ");
        out.print("\t" + this.timeEncryption / test_round);
        out.println();

        //write decapsulation
        out.print("Decapsulation: ");
        out.print("\t" + this.timeDecapsulation / test_round);
        out.println();

        //write decryption
        out.print("Decryption: ");
        out.print("\t" + this.timeDecryption / test_round);
        out.println();
    }

    private void run_one_round() {
        try {
            PairingParameters pairingParameters = PairingFactory.getPairingParameters(pairingParameterPath);
            Pairing pairing = PairingFactory.getPairing(pairingParameters);

            double temperTime;
            Timer timer = new Timer();
            //test setup performance
            System.out.print("Setup; ");
            out.print("Setup : ");
            timer.start(0);
            PairingKeySerPair keyPair = engine.setup(pairingParameters);
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeSetup += temperTime;
            out.println();
            System.out.println();

            PairingKeySerParameter publicKey = keyPair.getPublic();
            PairingKeySerParameter masterKey = keyPair.getPrivate();

            //test secret key generation performance
            System.out.print("KeyGen;");
            out.print("KeyGen: ");
            timer.start(0);
            PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, identity);
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeKeyGen += temperTime;
            out.println();
            System.out.println();

            //test encapsulation performance
            out.print("Encapsulation: ");
            System.out.print("Encapsulation: ");
            timer.start(0);
            PairingCipherSerParameter header = engine.encapsulation(publicKey, identity).getHeader();
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeEncapsulation += temperTime;
            out.println();
            System.out.println();

            //test encryption performance
            out.print("Encryption: ");
            System.out.print("Encryption: ");
            Element message = pairing.getGT().newRandomElement().getImmutable();
            timer.start(0);
            PairingCipherSerParameter ciphertext = engine.encryption(publicKey, identity, message);
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeEncryption += temperTime;
            out.println();
            System.out.println();

            //test decapsulation performance
            out.print("Decapsulation: ");
            System.out.print("Decapsulation: ");
            timer.start(0);
            engine.decapsulation(publicKey, secretKey, identity, header);
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeDecapsulation += temperTime;
            out.println();
            System.out.println();

            //test decryption performance
            out.print("Decryption: ");
            System.out.print("Decryption: ");
            timer.start(0);
            engine.decryption(publicKey, secretKey, identity, ciphertext);
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeDecryption += temperTime;
            out.println();
            System.out.println();
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }

    public void testBF01aPerformance() {
        IBEPerformanceTest performanceTest = new IBEPerformanceTest();
        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        performanceTest.engine = IBEBF01aEngine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }

    public void testGen06aPerformance() {
        IBEPerformanceTest performanceTest = new IBEPerformanceTest();
        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        performanceTest.engine = IBEGen06aEngine.getInstance();
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }
}

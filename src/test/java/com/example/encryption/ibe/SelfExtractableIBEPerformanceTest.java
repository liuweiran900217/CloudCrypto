package com.example.encryption.ibe;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.SelfExtractableIBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.IBEBF01aEngine;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.IBEGen06aEngine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.utils.Timer;
import com.example.TestUtils;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S1ParametersGenerator;

/**
 * Created by Weiran Liu on 2016/12/5.
 *
 * Self-extractable IBE performance test.
 */
public class SelfExtractableIBEPerformanceTest extends TestCase {
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
    private double timeSelfKeyGen;

    //key encapsulation time
    private double timeEncapsulation;

    //decapsulation time
    private double timeDecapsulation;
    private double timeSelfDecapsulation;

    private SelfExtractableIBEEngine engine;

    private Out out;

    private void init() {
        this.identity = "ID";
    }

    private void runPerformanceTest() {
        out = new Out(default_path + engine.getEngineName());
        out.println("Test Self-Extractable IBE engine: " + engine.getEngineName());
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

        //write SelfKeyGen
        out.print("SelfKeyGen: ");
        out.print("\t" + this.timeSelfKeyGen / test_round);
        out.println();

        //write encapsulation
        out.print("Encapsulation: ");
        out.print("\t" + this.timeEncapsulation / test_round);
        out.println();

        //write decapsulation
        out.print("Decapsulation: ");
        out.print("\t" + this.timeDecapsulation / test_round);
        out.println();

        //write decryption
        out.print("SelfDecapsulation: ");
        out.print("\t" + this.timeSelfDecapsulation / test_round);
        out.println();
    }

    private void run_one_round() {
        try {
            PairingParameters pairingParameters = PairingFactory.getPairingParameters(pairingParameterPath);

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

            //test self key generation
            System.out.print("SelfKeyGen;");
            out.print("SelfKeyGen: ");
            timer.start(0);
            byte[] ek = engine.selfKeyGen();
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeSelfKeyGen += temperTime;
            out.println();
            System.out.println();

            //test encapsulation performance
            out.print("Encapsulation: ");
            System.out.print("Encapsulation: ");
            timer.start(0);
            PairingCipherSerParameter header = engine.encapsulation(publicKey, identity, ek).getHeader();
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeEncapsulation += temperTime;
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
            out.print("SelfDecapsulation: ");
            System.out.print("SelfDecapsulation: ");
            timer.start(0);
            engine.selfDecapsulation(ek, header);
            temperTime = timer.stop(0);
            out.print("\t" + temperTime);
            this.timeSelfDecapsulation += temperTime;
            out.println();
            System.out.println();
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }

    public void testBF01aPerformance() {
        SelfExtractableIBEPerformanceTest performanceTest = new SelfExtractableIBEPerformanceTest();
        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        Digest digest = new SHA256Digest();
        IBEEngine ibeEngine = IBEBF01aEngine.getInstance();
        BlockCipher blockCipher = new AESEngine();
        PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
        performanceTest.engine = new SelfExtractableIBEEngine(ibeEngine, pbeParametersGenerator, blockCipher, digest);
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }

    public void testGen06aPerformance() {
        SelfExtractableIBEPerformanceTest performanceTest = new SelfExtractableIBEPerformanceTest();
        performanceTest.pairingParameterPath = PairingUtils.PATH_a_160_512;
        performanceTest.test_round = TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND;
        Digest digest = new SHA256Digest();
        IBEEngine ibeEngine = IBEGen06aEngine.getInstance();
        BlockCipher blockCipher = new AESEngine();
        PBEParametersGenerator pbeParametersGenerator = new PKCS5S1ParametersGenerator(digest);
        performanceTest.engine = new SelfExtractableIBEEngine(ibeEngine, pbeParametersGenerator, blockCipher, digest);
        performanceTest.init();
        performanceTest.runPerformanceTest();
    }
}

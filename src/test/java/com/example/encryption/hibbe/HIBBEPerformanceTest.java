package com.example.encryption.hibbe;

import cn.edu.buaa.crypto.algebra.generators.PairingParametersGenerator;
import cn.edu.buaa.crypto.algebra.params.PairingKeyEncapsulationPair;
import cn.edu.buaa.crypto.algebra.params.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import cn.edu.buaa.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/7.
 *
 * HIBBE scheme performance test.
 */
public class HIBBEPerformanceTest {
    //file path for performance test result
    private static final String default_path = "benchmarks/encryption/hibbe/";
    //the test round is chosen according to the full version of our paper.
    private int test_round = 25;
    //the maximal depth of roles is chosen according to the full version of our paper.
    private static final int maximal_depth = 10;
    //the maximal number of role index is chosen
    private static final int maximal_users = 100;

    private int qBitLength = 512;
    private int rBitLength = 160;
    //setup time
    private double timeSetep;

    //identity vectors
    private String[][] identityVectors = new String[maximal_depth][maximal_users];
    //secret key generation time
    private double[] timeKeyGen = new double[maximal_depth];

    //secret key delegation time
    private double[] timeKeyDele = new double[maximal_depth];

    //identity vector sets for key encapsulation
    private String[][] encapsulationIdentityVectorSets = new String[maximal_users][maximal_users];
    //key encapsulation time
    private double[] timeEncapsulation = new double[maximal_users];

    //decapsulation time
    private double[][] timeEHRDecapsulationM = new double[maximal_depth][maximal_users];

    private HIBBEEngine engine;
    private PairingParameters pairingParameters;

    private Out out;

    public HIBBEPerformanceTest(HIBBEEngine engine, String name) {
        this.engine = engine;
        out = new Out(default_path + name);

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

    public void setTestRound(int round) {
        this.test_round = round;
    }

    public void setRBitLength(int rBitLength) {
        this.rBitLength = rBitLength;
    }

    public void setQBitLength(int qBitLength) {
        this.qBitLength = qBitLength;
    }

    public void performanceTest() {
        for (int i = 0; i < test_round; i++) {
            System.out.println("Test round: " + (i+1));
            out.println("Test round: " + (i+1));
            test_one_round();
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
        out.print("Encrypt: ");
        for (int i = 0; i < maximal_users; i++) {
            out.print("\t" + this.timeEncapsulation[i] / test_round);
        }
        out.println();

        //write Decrypt
        for (int i = 0; i < maximal_depth; i++) {
            out.print("EHRDecM " + i + ": ");
            for (int j = i; j < maximal_users; j++) {
                out.print("\t" + this.timeEHRDecapsulationM[i][j] / test_round);
            }
            out.println();
        }
        out.println();
    }

    private void test_one_round() {
        if (this.engine instanceof HIBBELLW14Engine) {
            PairingParametersGenerationParameters pairingParametersGenerationParameters =
                    new PairingParametersGenerationParameters(3, qBitLength);
            PairingParametersGenerator pairingParametersGenerator = new PairingParametersGenerator();
            pairingParametersGenerator.init(pairingParametersGenerationParameters);
            this.pairingParameters = pairingParametersGenerator.generateParameters();
        }

        double temperTime;
        Timer timer = new Timer(maximal_users);
        //test setup performance
        System.out.print("Setup; ");
        out.print("Setup : ");
        timer.start(0);
        AsymmetricCipherKeyPair keyPair = engine.setup(pairingParameters, maximal_users);
        temperTime = timer.stop(0);
        out.print("\t" + temperTime);
        this.timeSetep += temperTime;
        out.println();

        CipherParameters publicKey = keyPair.getPublic();
        CipherParameters masterKey = keyPair.getPrivate();

        System.out.print("KeyGen; ");
        out.print("KeyGen: ");
        //test secret key generation performance
        CipherParameters[] secretKeys = new CipherParameters[maximal_depth];
        for (int i = 0; i < maximal_depth; i++) {
            timer.start(i);
            secretKeys[i] = engine.keyGen(publicKey, masterKey, identityVectors[i]);
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeKeyGen[i] += temperTime;
        }
        out.println();

        System.out.print("Delegate; ");
        out.print("Delegate: ");
        //test secret key delegation performance
        CipherParameters[] delegateKeys = new CipherParameters[maximal_depth];
        for (int i = 0; i < maximal_depth - 1; i++) {
            timer.start(i + 1);
            delegateKeys[i + 1] = engine.delegate(publicKey, secretKeys[i], i + 1, "Delegate");
            temperTime = timer.stop(i + 1);
            out.print("\t" + temperTime);
            this.timeKeyDele[i + 1] += temperTime;
        }
        out.println();

        System.out.print("Encrypt; ");
        out.print("Encrypt: ");
        //test key encapsulation performance
        CipherParameters[] encapsulations = new CipherParameters[maximal_users];
        for (int i = 0; i < maximal_users; i++) {
            timer.start(i);
            PairingKeyEncapsulationPair encapsulationPair = engine.encapsulation(publicKey, encapsulationIdentityVectorSets[i]);
            encapsulations[i] = encapsulationPair.getCiphertext();
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeEncapsulation[i] += temperTime;
        }
        out.println();

        //test decapsulation performance
        for (int i = 0; i < maximal_depth; i++) {
            System.out.print("Decrypt " + i + "; ");
            out.print("Decrypt " + i + ": ");
            for (int j = i; j < maximal_users; j++) {
                try {
                    timer.start(i);
                    engine.decapsulation(publicKey, secretKeys[i], encapsulationIdentityVectorSets[j], encapsulations[j]);
                    temperTime = timer.stop(i);
                    out.print("\t" + temperTime);
                    this.timeEHRDecapsulationM[i][j] += temperTime;
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
}
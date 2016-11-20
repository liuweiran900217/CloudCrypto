package com.example.encryption.hibbe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.utils.Timer;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/11/7.
 *
 * HIBBE scheme performance test.
 */
public class HIBBEPerformanceTest {
    private final String pairingParameterPath;
    //file path for performance test result
    private static final String default_path = "benchmarks/encryption/hibbe/";
    private int test_round;
    //the maximal depth of roles is chosen according to the full version of our paper.
    private static final int maximal_depth = 10;
    //the maximal number of role index is chosen
    private static final int maximal_users = 100;
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

    private Out out;

    public HIBBEPerformanceTest(String paringParameterPath, int test_round, HIBBEEngine engine, String name) {
        this.pairingParameterPath = paringParameterPath;
        this.engine = engine;
        this.test_round = test_round;

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
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(pairingParameterPath);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);

        double temperTime;
        Timer timer = new Timer(maximal_users);
        //test setup performance
        System.out.print("Setup; ");
        out.print("Setup : ");
        timer.start(0);
        AsymmetricKeySerPair keyPair = engine.setup(pairingParameters, maximal_users);
        temperTime = timer.stop(0);
        out.print("\t" + temperTime);
        this.timeSetep += temperTime;
        out.println();

        AsymmetricKeySerParameter publicKey = keyPair.getPublic();
        AsymmetricKeySerParameter masterKey = keyPair.getPrivate();

        System.out.print("KeyGen; ");
        out.print("KeyGen: ");
        //test secret key generation performance
        AsymmetricKeySerParameter[] secretKeys = new AsymmetricKeySerParameter[maximal_depth];
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
        AsymmetricKeySerParameter[] delegateKeys = new AsymmetricKeySerParameter[maximal_depth];
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
        //test encryption performance
        PairingCipherSerParameter[] ciphertexts = new PairingCipherSerParameter[maximal_users];
        for (int i = 0; i < maximal_users; i++) {
            Element message = pairing.getGT().newRandomElement().getImmutable();
            timer.start(i);
            ciphertexts[i] = engine.encryption(publicKey, encapsulationIdentityVectorSets[i], message);
            temperTime = timer.stop(i);
            out.print("\t" + temperTime);
            this.timeEncapsulation[i] += temperTime;
        }
        out.println();

        //test decryption performance
        for (int i = 0; i < maximal_depth; i++) {
            System.out.print("Decrypt " + i + "; ");
            out.print("Decrypt " + i + ": ");
            for (int j = i; j < maximal_users; j++) {
                try {
                    timer.start(i);
                    engine.decryption(publicKey, secretKeys[i], encapsulationIdentityVectorSets[j], ciphertexts[j]);
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
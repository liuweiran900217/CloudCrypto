package com.example.encryption.hibe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * HIBE engine test procedures. All instances should pass this unit test.
 */
public class HIBEEngineTest {
    private HIBEEngine engine;

    public HIBEEngineTest(HIBEEngine engine) {
        this.engine = engine;
    }

    public void processTest(PairingParameters pairingParameters, int maxDepth) {
        // Setup
        AsymmetricKeySerPair keyPair = engine.setup(pairingParameters, maxDepth);
        AsymmetricKeySerParameter publicKey = keyPair.getPublic();
        AsymmetricKeySerParameter masterKey = keyPair.getPrivate();

        // KeyGen
        String[] ids = {"ID_1", "ID_2", "ID_3"};

        AsymmetricKeySerParameter sk0 = engine.keyGen(publicKey, masterKey, ids[0]);
        AsymmetricKeySerParameter sk01 = engine.keyGen(publicKey, masterKey, ids[0], ids[1]);
        AsymmetricKeySerParameter sk012 = engine.keyGen(publicKey, masterKey, ids[0], ids[1], ids[2]);

        AsymmetricKeySerParameter sk1 = engine.keyGen(publicKey, masterKey, ids[1]);
        AsymmetricKeySerParameter sk10 = engine.keyGen(publicKey, masterKey, ids[1], ids[0]);
        AsymmetricKeySerParameter sk021 = engine.keyGen(publicKey, masterKey, ids[0], ids[2], ids[1]);

        // Encryption
        String[] ids0 = new String[]{ids[0]};
        PairingKeyEncapsulationSerPair ciphertextPair0 = engine.encapsulation(publicKey, ids[0]);
        PairingCipherSerParameter ciphertext0 = ciphertextPair0.getCiphertext();
        byte[] sessionKey0 = ciphertextPair0.getSessionKey();
        String stringSessionKey0 = new String(Hex.encode(sessionKey0));

        String[] ids01 = new String[]{ids[0], ids[1]};
        PairingKeyEncapsulationSerPair ciphertextPair01 = engine.encapsulation(publicKey, ids[0], ids[1]);
        PairingCipherSerParameter ciphertext01 = ciphertextPair01.getCiphertext();
        byte[] sessionKey01 = ciphertextPair01.getSessionKey();
        String stringSessionKey01 = new String(Hex.encode(sessionKey01));

        String[] ids012 = new String[]{ids[0], ids[1], ids[2]};
        PairingKeyEncapsulationSerPair ciphertextPair012 = engine.encapsulation(publicKey, ids[0], ids[1], ids[2]);
        PairingCipherSerParameter ciphertext012 = ciphertextPair012.getCiphertext();
        byte[] sessionKey012 = ciphertextPair012.getSessionKey();
        String stringSessionKey012 = new String(Hex.encode(sessionKey012));

        // Decrypt with correct secret keys
        System.out.println("========================================");
        System.out.println("Test decrypting with correct secret keys");
        try {
            //Decrypt ciphertext 0 using secret key 0
            System.out.println("Test decrypting ciphertext 0 using secret key 0");
            String sessionKey =  new String(Hex.encode(engine.decapsulation(publicKey, sk0, ids0, ciphertext0)));
            assertEquals(stringSessionKey0, sessionKey);
            System.out.println("Expect:" + stringSessionKey0 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 01 using secret key 01
            System.out.println("Test decrypting ciphertext 01 using secret key 01");
            String sessionKey = new String(Hex.encode(engine.decapsulation(publicKey, sk01, ids01, ciphertext01)));
            assertEquals(stringSessionKey01, sessionKey);
            System.out.println("Expect:" + stringSessionKey01 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 012 using secret key 012
            System.out.println("Test decrypting ciphertext 012 using secret key 012");
            String sessionKey = new String(Hex.encode(engine.decapsulation(publicKey, sk012, ids012, ciphertext012)));
            assertEquals(stringSessionKey012, sessionKey);
            System.out.println("Expect:" + stringSessionKey012 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 01 using secret key 0
            System.out.println("Test decrypting ciphertext 01 using secret key 0");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, sk0, ids01, ciphertextPair01.getCiphertext()
            )));
            assertEquals(stringSessionKey01, sessionKey);
            System.out.println("Expect:" + stringSessionKey01 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 012 using secret key 0
            System.out.println("Test decrypting ciphertext 012 using secret key 0");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, sk0, ids012, ciphertextPair012.getCiphertext()
            )));
            assertEquals(stringSessionKey012, sessionKey);
            System.out.println("Expect:" + stringSessionKey012 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 012 using secret key 01
            System.out.println("Test decrypting ciphertext 012 using secret key 01");
            String sessionKey =new String(Hex.encode(engine.decapsulation(
                    publicKey, sk01, ids012, ciphertextPair012.getCiphertext()
            )));
            assertEquals(stringSessionKey012, sessionKey);
            System.out.println("Expect:" + stringSessionKey012 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }

        //Decrypt with incorrect secret keys
        System.out.println("==========================================");
        System.out.println("Test decrypting with incorrect secret keys");
        try {
            //Decrypt ciphertext 0 using secret key 1
            System.out.println("Test decrypting ciphertext 0 using secret key 1");
            assertEquals(false, stringSessionKey0.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk1,
                            ids0,
                            ciphertextPair0.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext 01 using secret key 10
            System.out.println("Test decrypting ciphertext 01 using secret key 10");
            assertEquals(false, stringSessionKey01.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk10,
                            ids01,
                            ciphertextPair01.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext 012 using secret key 021
            System.out.println("Test decrypting ciphertext 012 using secret key 021");
            assertEquals(false, stringSessionKey012.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk021,
                            ids012,
                            ciphertextPair012.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e){
            //Correct if getting there, nothing to do
        }

        //Delegate & Correct Decrypt
        System.out.println("======================================");
        System.out.println("Test delegating and correct decrypting");
        try {
            //Delegate sk01 using sk0 and decrypt
            System.out.println("Test delegating sk01 using sk0 and decrypting");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, sk0, ids[1]), ids01, ciphertextPair01.getCiphertext()
            )));
            assertEquals(stringSessionKey01, sessionKey);
            System.out.println("Expect:" + stringSessionKey01 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Delegate sk012 using sk01 and decrypt
            System.out.println("Test delegating sk012 using sk01 and decrypting");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, sk01, ids[2]), ids012, ciphertextPair012.getCiphertext()
            )));
            assertEquals(stringSessionKey012, sessionKey);
            System.out.println("Expect:" + stringSessionKey012 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Delegate sk012 using sk0 and decrypt
            System.out.println("Test delegating sk012 using sk0 and decrypting");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, engine.delegate(publicKey, sk0, ids[1]), ids[2]),
                    ids012, ciphertextPair012.getCiphertext()
            )));
            assertEquals(stringSessionKey012, sessionKey);
            System.out.println("Expect:" + stringSessionKey012 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        //Delegate & Incorrect Decrypt
        System.out.println("========================================");
        System.out.println("Test delegating and incorrect decrypting");
        try {
            System.out.println("Test delegating sk00 and decrypting ciphertext 01");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, sk0, ids[0]),
                    ids01, ciphertextPair01.getCiphertext()
            )));
            assertEquals(false, stringSessionKey01.equals(sessionKey));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            System.out.println("Test delegating sk011 and decrypting ciphertext 012");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, sk01, ids[1]),
                    ids012, ciphertextPair012.getCiphertext()
            )));
            assertEquals(false, stringSessionKey012.equals(sessionKey));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            System.out.println("Test delegating sk02 and decrypting ciphertext 012");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, sk0, ids[2]),
                    ids012, ciphertextPair012.getCiphertext()
            )));
            assertEquals(false, stringSessionKey012.equals(sessionKey));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        System.out.println("======================================");
        System.out.println("HIBE Engine tests passed.");

        //Test Serialize & deserialize
        //Test Serialize & deserialize
        System.out.println("======================================");
        System.out.println("Test HIBE parameter serialization & de-serialization.");
        try {
            //serialize public key
            System.out.println("Test serialize & de-serialize public key.");
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            assertEquals(publicKey, anPublicKey);

            //serialize master secret key
            System.out.println("Test serialize & de-serialize master secret key.");
            byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
            CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
            assertEquals(masterKey, anMasterKey);

            //serialize secret key
            System.out.println("Test serialize & de-serialize secret keys.");
            //serialize sk4
            byte[] byteArraySk0 = TestUtils.SerCipherParameter(sk0);
            CipherParameters anSk0 = TestUtils.deserCipherParameters(byteArraySk0);
            assertEquals(sk0, anSk0);
            //serialize sk46
            byte[] byteArraySk01 = TestUtils.SerCipherParameter(sk01);
            CipherParameters anSk01 = TestUtils.deserCipherParameters(byteArraySk01);
            assertEquals(sk01, anSk01);
            //serialize sk467
            byte[] byteArraySk012 = TestUtils.SerCipherParameter(sk012);
            CipherParameters anSk012 = TestUtils.deserCipherParameters(byteArraySk012);
            assertEquals(sk012, anSk012);

            //serialize ciphertext
            System.out.println("Test serialize & de-serialize ciphertexts.");
            byte[] byteArrayCiphertext0 = TestUtils.SerCipherParameter(ciphertext0);
            CipherParameters anCiphertext0 = TestUtils.deserCipherParameters(byteArrayCiphertext0);
            assertEquals(ciphertext0, anCiphertext0);
            byte[] byteArrayCiphertext01 = TestUtils.SerCipherParameter(ciphertext01);
            CipherParameters anCiphertext01 = TestUtils.deserCipherParameters(byteArrayCiphertext01);
            assertEquals(ciphertext01, anCiphertext01);
            byte[] byteArrayCiphertext012 = TestUtils.SerCipherParameter(ciphertext012);
            CipherParameters anCiphertext012 = TestUtils.deserCipherParameters(byteArrayCiphertext012);
            assertEquals(ciphertext012, anCiphertext012);

            System.out.println("HIBE parameter serialization tests passed.");
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}

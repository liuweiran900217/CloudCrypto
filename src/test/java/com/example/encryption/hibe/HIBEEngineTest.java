package com.example.encryption.hibe;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;

import java.io.File;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * HIBE engine test procedures. All instances should pass this unit test.
 */
public class HIBEEngineTest {
    private HIBEEngine engine;
    private PairingParameterXMLSerializer schemeXMLSerializer;

    public HIBEEngineTest(HIBEEngine engine, PairingParameterXMLSerializer schemeXMLSerializer) {
        this.engine = engine;
        this.schemeXMLSerializer = schemeXMLSerializer;
    }

    public void processTest(int rBitLength, int qBitLength, int maxDepth) {
        // Setup
        AsymmetricCipherKeyPair keyPair = engine.setup(rBitLength, qBitLength, maxDepth);
        CipherParameters publicKey = keyPair.getPublic();
        CipherParameters masterKey = keyPair.getPrivate();
        PairingParameters pairingParameters = ((PairingKeyParameters)publicKey).getParameters();

        // KeyGen
        String[] ids = {"ID_1", "ID_2", "ID_3"};

        CipherParameters sk0 = engine.keyGen(publicKey, masterKey, ids[0]);
        CipherParameters sk01 = engine.keyGen(publicKey, masterKey, ids[0], ids[1]);
        CipherParameters sk012 = engine.keyGen(publicKey, masterKey, ids[0], ids[1], ids[2]);

        CipherParameters sk1 = engine.keyGen(publicKey, masterKey, ids[1]);
        CipherParameters sk10 = engine.keyGen(publicKey, masterKey, ids[1], ids[0]);
        CipherParameters sk021 = engine.keyGen(publicKey, masterKey, ids[0], ids[2], ids[1]);

        // Encryption
        String[] ids0 = new String[]{ids[0]};
        PairingKeyEncapsulationPair ciphertextPair0 = engine.encapsulation(publicKey, ids[0]);
        CipherParameters ciphertext0 = ciphertextPair0.getCiphertext();
        byte[] sessionKey0 = ciphertextPair0.getSessionKey();
        String stringSessionKey0 = new String(Hex.encode(sessionKey0));

        String[] ids01 = new String[]{ids[0], ids[1]};
        PairingKeyEncapsulationPair ciphertextPair01 = engine.encapsulation(publicKey, ids[0], ids[1]);
        CipherParameters ciphertext01 = ciphertextPair01.getCiphertext();
        byte[] sessionKey01 = ciphertextPair01.getSessionKey();
        String stringSessionKey01 = new String(Hex.encode(sessionKey01));

        String[] ids012 = new String[]{ids[0], ids[1], ids[2]};
        PairingKeyEncapsulationPair ciphertextPair012 = engine.encapsulation(publicKey, ids[0], ids[1], ids[2]);
        CipherParameters ciphertext012 = ciphertextPair012.getCiphertext();
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
        if (this.schemeXMLSerializer != null) {
            File file = new File("serializations/hibe");
            file.mkdir();

            //Serialize & deserialize public key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing public key");
            TestUtils.OutputXMLDocument("serializations/hibe/HIBE_Public_Key.xml", schemeXMLSerializer.documentSerialization(publicKey));
            Document documentPublicKey = TestUtils.InputXMLDocument("serializations/hibe/HIBE_Public_Key.xml");
            CipherParameters anoPublicKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentPublicKey);
            assertEquals(publicKey, anoPublicKey);

            //Serialize & deserialize master secret key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing master secret key");
            TestUtils.OutputXMLDocument("serializations/hibe/HIBE_Master_Secret_Key.xml", schemeXMLSerializer.documentSerialization(masterKey));
            Document documentMasterKey = TestUtils.InputXMLDocument("serializations/hibe/HIBE_Master_Secret_Key.xml");
            CipherParameters anoMasterKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentMasterKey);
            assertEquals(masterKey, anoMasterKey);


            //Serialize & deserialize secret keys
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key 0");
            //Serialize & deserialize sk0
            TestUtils.OutputXMLDocument("serializations/hibe/HIBE_Secret_Key_0.xml", schemeXMLSerializer.documentSerialization(sk0));
            Document documentSk0 = TestUtils.InputXMLDocument("serializations/hibe/HIBE_Secret_Key_0.xml");
            CipherParameters anSk0 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSk0);
            assertEquals(sk0, anSk0);
            //Serialize & deserialize sk01
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key 01");
            TestUtils.OutputXMLDocument("serializations/hibe/HIBE_Secret_Key_01.xml",schemeXMLSerializer.documentSerialization(sk01));
            Document documentSk01 = TestUtils.InputXMLDocument("serializations/hibe/HIBE_Secret_Key_01.xml");
            CipherParameters anSk01 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSk01);
            assertEquals(sk01, anSk01);
            //Serialize & deserialize sk012
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key 012");
            TestUtils.OutputXMLDocument("serializations/hibe/HIBE_Secret_Key_012.xml", schemeXMLSerializer.documentSerialization(sk012));
            Document documentSk012 = TestUtils.InputXMLDocument("serializations/hibe/HIBE_Secret_Key_012.xml");
            CipherParameters anSk012 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSk012);
            assertEquals(sk012, anSk012);

            //Serialize & deserialize ciphertexts
            //Serialize & deserialize ciphertext0
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext 0");
            TestUtils.OutputXMLDocument("serializations/hibe/HIBE_Ciphertext_0.xml", schemeXMLSerializer.documentSerialization(ciphertext0));
            Document documentCiphertext0 = TestUtils.InputXMLDocument("serializations/hibe/HIBE_Ciphertext_0.xml");
            CipherParameters anCiphertext0 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertext0);
            assertEquals(ciphertext0, anCiphertext0);
            //Serialize & deserialize ciphertext01
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext 01");
            TestUtils.OutputXMLDocument("serializations/hibe/HIBE_Ciphertext_01.xml", schemeXMLSerializer.documentSerialization(ciphertext01));
            Document documentCiphertext01 = TestUtils.InputXMLDocument("serializations/hibe/HIBE_Ciphertext_01.xml");
            CipherParameters anCiphertext01 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertext01);
            assertEquals(ciphertext01, anCiphertext01);
            //Serialize & deserialize ciphertext012
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext 012");
            TestUtils.OutputXMLDocument("serializations/hibe/HIBE_Ciphertext_012.xml", schemeXMLSerializer.documentSerialization(ciphertext012));
            Document documentCiphertext012 = TestUtils.InputXMLDocument("serializations/hibe/HIBE_Ciphertext_012.xml");
            CipherParameters anCiphertext012 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertext012);
            assertEquals(ciphertext012, anCiphertext012);

            System.out.println("======================================");
            System.out.println("Serialize & deserialize tests passed.");
        }
    }
}

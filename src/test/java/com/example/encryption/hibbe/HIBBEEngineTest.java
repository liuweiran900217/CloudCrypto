package com.example.encryption.hibbe;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
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
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE engine test procedures. All instances should pass this unit test.
 */
public class HIBBEEngineTest {
    private HIBBEEngine engine;
    private PairingParameterXMLSerializer schemeXMLSerializer;

    public HIBBEEngineTest(HIBBEEngine engine, PairingParameterXMLSerializer schemeXMLSerializer) {
        this.engine = engine;
        this.schemeXMLSerializer = schemeXMLSerializer;
    }

    public void processTest(int rBitLength, int qBitLength) {
        // Setup
        AsymmetricCipherKeyPair keyPair = engine.setup(rBitLength, qBitLength, 8);
        CipherParameters publicKey = keyPair.getPublic();
        CipherParameters masterKey = keyPair.getPrivate();
        PairingParameters pairingParameters = ((PairingKeyParameters)publicKey).getParameters();

        // KeyGen
        String[] id4    = {null,    null,   null,   "ID_4", null,   null,   null,   null};
        String[] id46   = {null,    null,   null,   "ID_4", null,   "ID_6", null,   null};
        String[] id467  = {null,    null,   null,   "ID_4", null,   "ID_6", "ID_7", null};
        String[] id45   = {null,    null,   null,   "ID_4", "ID_5", null,   null,   null};
        String[] id3    = {"ID_3",  null,   null,   null,   null,   null,   null,   null};
        String[] id31   = {"ID_3",  null,   "ID_1", null,   null,   null,   null,   null};

        String[] ivs13467  = {"ID_1",  null,   "ID_3", "ID_4", null,   "ID_6", "ID_7", null};

        CipherParameters sk4 = engine.keyGen(publicKey, masterKey, id4);
        CipherParameters sk46 = engine.keyGen(publicKey, masterKey, id46);
        CipherParameters sk467 = engine.keyGen(publicKey, masterKey, id467);
        CipherParameters sk45 = engine.keyGen(publicKey, masterKey, id45);
        CipherParameters sk3 = engine.keyGen(publicKey, masterKey, id3);
        CipherParameters sk31 = engine.keyGen(publicKey, masterKey, id31);

        // Encryption
        PairingKeyEncapsulationPair ciphertextPair13467 = engine.encapsulation(publicKey, ivs13467);
        CipherParameters ciphertext13467 = ciphertextPair13467.getCiphertext();
        byte[] sessionKey13467 = ciphertextPair13467.getSessionKey();
        String stringSessionKey13467 = new String(Hex.encode(sessionKey13467));

        // Decrypt with correct secret keys
        System.out.println("========================================");
        System.out.println("Test decrypting with correct secret keys");
        try {
            //Decrypt ciphertext 13467 using secret key 4
            System.out.println("Test decrypting ciphertext 13467 using secret key 4");
            String sessionKey =  new String(Hex.encode(engine.decapsulation(publicKey, sk4, ivs13467, ciphertext13467)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 13467 using secret key 46
            System.out.println("Test decrypting ciphertext 13467 using secret key 46");
            String sessionKey = new String(Hex.encode(engine.decapsulation(publicKey, sk46, ivs13467, ciphertext13467)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 13467 using secret key 467
            System.out.println("Test decrypting ciphertext 13467 using secret key 467");
            String sessionKey = new String(Hex.encode(engine.decapsulation(publicKey, sk467, ivs13467, ciphertext13467)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }

        //Decrypt with incorrect secret keys
        System.out.println("==========================================");
        System.out.println("Test decrypting with incorrect secret keys");
        try {
            //Decrypt ciphertext 13467 using secret key 45
            System.out.println("Test decrypting ciphertext 13467 using secret key 45");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk45,
                            ivs13467,
                            ciphertextPair13467.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext 13467 using secret key 3
            System.out.println("Test decrypting ciphertext 13467 using secret key 3");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk3,
                            ivs13467,
                            ciphertextPair13467.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext 13467 using secret key 31
            System.out.println("Test decrypting ciphertext 13467 using secret key 31");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk31,
                            ivs13467,
                            ciphertextPair13467.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e){
            //Correct if getting there, nothing to do
        }

        //Delegate & Correct Decrypt
        System.out.println("======================================");
        System.out.println("Test delegating and correct decrypting");
        try {
            //Delegate sk46 using sk4 and decrypt
            System.out.println("Test delegating sk46 using sk4 and decrypting");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, sk4, 5, "ID_6"), ivs13467, ciphertextPair13467.getCiphertext()
            )));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Delegate sk467 using sk46 and decrypt
            System.out.println("Test delegating sk467 using sk46 and decrypting");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, sk46, 6, "ID_7"), ivs13467, ciphertextPair13467.getCiphertext()
            )));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Delegate sk467 using sk4 and decrypt
            System.out.println("Test delegating sk012 using sk0 and decrypting");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, engine.delegate(publicKey, sk4, 5, "ID_6"), 6, "ID_7"),
                    ivs13467, ciphertextPair13467.getCiphertext()
            )));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        //Delegate & Incorrect Decrypt
        System.out.println("========================================");
        System.out.println("Test delegating and incorrect decrypting");
        try {
            System.out.println("Test delegating sk31 and decrypting ciphertext 13467");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, sk3, 2, "ID_1"),
                    ivs13467, ciphertextPair13467.getCiphertext()
            )));
            assertEquals(false, stringSessionKey13467.equals(sessionKey));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        System.out.println("======================================");
        System.out.println("HIBBE Engine tests passed.");

        //Test Serialize & deserialize
        if (this.schemeXMLSerializer != null) {
            File file = new File("serializations/hibbe");
            file.mkdir();

            //Serialize & deserialize public key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing public key");
            TestUtils.OutputXMLDocument("serializations/hibbe/HIBBE_Public_Key.xml", schemeXMLSerializer.documentSerialization(publicKey));
            Document documentPublicKey = TestUtils.InputXMLDocument("serializations/hibbe/HIBBE_Public_Key.xml");
            CipherParameters anoPublicKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentPublicKey);
            assertEquals(publicKey, anoPublicKey);

            //Serialize & deserialize master secret key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing master secret key");
            TestUtils.OutputXMLDocument("serializations/hibbe/HIBBE_Master_Secret_Key.xml", schemeXMLSerializer.documentSerialization(masterKey));
            Document documentMasterKey = TestUtils.InputXMLDocument("serializations/hibbe/HIBBE_Master_Secret_Key.xml");
            CipherParameters anoMasterKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentMasterKey);
            assertEquals(masterKey, anoMasterKey);

            //Serialize & deserialize secret keys
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key 4");
            //Serialize & deserialize sk4
            TestUtils.OutputXMLDocument("serializations/hibbe/HIBBE_Secret_Key_4.xml", schemeXMLSerializer.documentSerialization(sk4));
            Document documentSk4 = TestUtils.InputXMLDocument("serializations/hibbe/HIBBE_Secret_Key_4.xml");
            CipherParameters anSk4 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSk4);
            assertEquals(sk4, anSk4);
            //Serialize & deserialize sk46
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key 46");
            TestUtils.OutputXMLDocument("serializations/hibbe/HIBBE_Secret_Key_46.xml",schemeXMLSerializer.documentSerialization(sk46));
            Document documentSk46 = TestUtils.InputXMLDocument("serializations/hibbe/HIBBE_Secret_Key_46.xml");
            CipherParameters anSk46 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSk46);
            assertEquals(sk46, anSk46);
            //Serialize & deserialize sk467
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key 467");
            TestUtils.OutputXMLDocument("serializations/hibbe/HIBBE_Secret_Key_467.xml", schemeXMLSerializer.documentSerialization(sk467));
            Document documentSk467 = TestUtils.InputXMLDocument("serializations/hibbe/HIBBE_Secret_Key_467.xml");
            CipherParameters anSk467 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSk467);
            assertEquals(sk467, anSk467);

            //Serialize & deserialize ciphertexts
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext 13467");
            TestUtils.OutputXMLDocument("serializations/hibbe/HIBBE_Ciphertext_13467.xml", schemeXMLSerializer.documentSerialization(ciphertext13467));
            Document documentCiphertext13467 = TestUtils.InputXMLDocument("serializations/hibbe/HIBBE_Ciphertext_13467.xml");
            CipherParameters anCiphertext13467 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertext13467);
            assertEquals(ciphertext13467, anCiphertext13467);

            System.out.println("======================================");
            System.out.println("Serialize & deserialize tests passed.");
        }
    }
}

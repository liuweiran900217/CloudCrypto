package com.example.encryption.hibbe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * HIBBE engine test procedures. All instances should pass this unit test.
 */
public class HIBBEEngineTest {
    private HIBBEEngine engine;

    public HIBBEEngineTest(HIBBEEngine engine) {
        this.engine = engine;
    }

    public void processTest(PairingParameters pairingParameters) {
        // Setup
        AsymmetricKeySerPair keyPair = engine.setup(pairingParameters, 8);
        AsymmetricKeySerParameter publicKey = keyPair.getPublic();
        AsymmetricKeySerParameter masterKey = keyPair.getPrivate();

        // KeyGen
        String[] id4    = {null,    null,   null,   "ID_4", null,   null,   null,   null};
        String[] id46   = {null,    null,   null,   "ID_4", null,   "ID_6", null,   null};
        String[] id467  = {null,    null,   null,   "ID_4", null,   "ID_6", "ID_7", null};
        String[] id45   = {null,    null,   null,   "ID_4", "ID_5", null,   null,   null};
        String[] id3    = {"ID_3",  null,   null,   null,   null,   null,   null,   null};
        String[] id31   = {"ID_3",  null,   "ID_1", null,   null,   null,   null,   null};

        String[] ivs13467  = {"ID_1",  null,   "ID_3", "ID_4", null,   "ID_6", "ID_7", null};

        AsymmetricKeySerParameter sk4 = engine.keyGen(publicKey, masterKey, id4);
        AsymmetricKeySerParameter sk46 = engine.keyGen(publicKey, masterKey, id46);
        AsymmetricKeySerParameter sk467 = engine.keyGen(publicKey, masterKey, id467);
        AsymmetricKeySerParameter sk45 = engine.keyGen(publicKey, masterKey, id45);
        AsymmetricKeySerParameter sk3 = engine.keyGen(publicKey, masterKey, id3);
        AsymmetricKeySerParameter sk31 = engine.keyGen(publicKey, masterKey, id31);

        // Encryption
        PairingKeyEncapsulationSerPair ciphertextPair13467 = engine.encapsulation(publicKey, ivs13467);
        CipherParameters ciphertext13467 = ciphertextPair13467.getCiphertext();
        byte[] sessionKey13467 = ciphertextPair13467.getSessionKey();
        String stringSessionKey13467 = new String(Hex.encode(sessionKey13467));

        // Decrypt with correct secret keys
        System.out.println("========================================");
        System.out.println("Test HIBBE engine functionality");
        try {
            //Decrypt ciphertext 13467 using secret key 4
            System.out.println("Test decrypting with correct secret keys");
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

        try {
            //Decrypt with incorrect secret keys
            System.out.println("Test decrypting with incorrect secret keys");
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

        try {
            //Delegate & Correct Decrypt
            System.out.println("Test delegating and correct decrypting");
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
        try {
            //Delegate & Incorrect Decrypt
            System.out.println("Test delegating and incorrect decrypting");
            System.out.println("Test delegating sk31 and decrypting ciphertext 13467");
            String sessionKey = new String(Hex.encode(engine.decapsulation(
                    publicKey, engine.delegate(publicKey, sk3, 2, "ID_1"),
                    ivs13467, ciphertextPair13467.getCiphertext()
            )));
            assertEquals(false, stringSessionKey13467.equals(sessionKey));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        System.out.println("HIBBE Engine functionality test passed.");
        System.out.println();

        //Test Serialize & deserialize
        System.out.println("======================================");
        System.out.println("Test HIBBE parameter serialization & de-serialization.");
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
            byte[] byteArraySk4 = TestUtils.SerCipherParameter(sk4);
            CipherParameters anSk4 = TestUtils.deserCipherParameters(byteArraySk4);
            assertEquals(sk4, anSk4);
            //serialize sk46
            byte[] byteArraySk46 = TestUtils.SerCipherParameter(sk46);
            CipherParameters anSk46 = TestUtils.deserCipherParameters(byteArraySk46);
            assertEquals(sk46, anSk46);
            //serialize sk467
            byte[] byteArraySk467 = TestUtils.SerCipherParameter(sk467);
            CipherParameters anSk467 = TestUtils.deserCipherParameters(byteArraySk467);
            assertEquals(sk467, anSk467);

            //serialize ciphertext
            System.out.println("Test serialize & de-serialize ciphertexts.");
            byte[] byteArrayCt13467 = TestUtils.SerCipherParameter(ciphertext13467);
            CipherParameters anCiphertext13467 = TestUtils.deserCipherParameters(byteArrayCt13467);
            assertEquals(ciphertext13467, anCiphertext13467);

            System.out.println("HIBBE parameter serialization tests passed.");
            System.out.println();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}

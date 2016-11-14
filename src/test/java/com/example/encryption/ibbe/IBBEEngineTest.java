package com.example.encryption.ibbe;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * IBBE engine test procedures. All instances should pass this unit test.
 */
public class IBBEEngineTest {
    private IBBEEngine engine;

    public IBBEEngineTest(IBBEEngine engine) {
        this.engine = engine;
    }

    public void processTest(PairingParameters pairingParameters) {
        // Setup
        AsymmetricKeySerPair keyPair = engine.setup(pairingParameters, 8);
        AsymmetricKeySerParameter publicKey = keyPair.getPublic();
        AsymmetricKeySerParameter masterKey = keyPair.getPrivate();

        // KeyGen
        String receiverID = "ID_0";
        String nonReceiverID = "ID_8";

        String[] receiverSet1 = {"ID_0"};
        String[] receiverSet4 = {"ID_2", "ID_3", "ID_1", "ID_0"};
        String[] receiverSet8 = {"ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0"};
        String[] receiverSet9 = {"ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0", "ID_8"};

        AsymmetricKeySerParameter skReceiverID = engine.keyGen(publicKey, masterKey, receiverID);
        AsymmetricKeySerParameter skNonReceiverID = engine.keyGen(publicKey, masterKey, nonReceiverID);

        // Encryption
        PairingKeyEncapsulationSerPair ciphertextPairSet1 = engine.encapsulation(publicKey, receiverSet1);
        PairingCipherSerParameter ciphertextSet1 = ciphertextPairSet1.getCiphertext();
        byte[] sessionKeySet1 = ciphertextPairSet1.getSessionKey();
        String stringSessionKeySet1 = new String(Hex.encode(sessionKeySet1));

        PairingKeyEncapsulationSerPair ciphertextPairSet4 = engine.encapsulation(publicKey, receiverSet4);
        PairingCipherSerParameter ciphertextSet4 = ciphertextPairSet4.getCiphertext();
        byte[] sessionKeySet4 = ciphertextPairSet4.getSessionKey();
        String stringSessionKeySet4 = new String(Hex.encode(sessionKeySet4));

        PairingKeyEncapsulationSerPair ciphertextPairSet8 = engine.encapsulation(publicKey, receiverSet8);
        PairingCipherSerParameter ciphertextSet8 = ciphertextPairSet8.getCiphertext();
        byte[] sessionKeySet8 = ciphertextPairSet8.getSessionKey();
        String stringSessionKeySet8 = new String(Hex.encode(sessionKeySet8));

        System.out.println("======================================");
        System.out.println("Test IBBE engine functionality.");
        // Decrypt with correct secret keys
        System.out.println("Test decrypting with correct secret key");
        try {
            //Decrypt ciphertext set 1 using secret key ID_0
            System.out.println("Test decrypting ciphertext set 1 using secret key ID_0");
            String sessionKey = new String(Hex.encode(engine.decapsulation(publicKey, skReceiverID, receiverSet1, ciphertextSet1)));
            assertEquals(stringSessionKeySet1, sessionKey);
            System.out.println("Expect:" + stringSessionKeySet1 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext set 4 using secret key ID_0
            System.out.println("Test decrypting ciphertext set 4 using secret key ID_0");
            String sessionKey = new String(Hex.encode(engine.decapsulation(publicKey, skReceiverID, receiverSet4, ciphertextSet4)));
            assertEquals(stringSessionKeySet4, sessionKey);
            System.out.println("Expect:" + stringSessionKeySet4 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext set 8 using secret key ID_0
            System.out.println("Test decrypting ciphertext set 8 using secret key ID_0");
            String sessionKey = new String(Hex.encode(engine.decapsulation(publicKey, skReceiverID, receiverSet8, ciphertextSet8)));
            assertEquals(stringSessionKeySet8, sessionKey);
            System.out.println("Expect:" + stringSessionKeySet8 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        //Decrypt with incorrect secret keys
        System.out.println("Test decrypting with incorrect secret keys");
        try {
            //Decrypt ciphertext set 1 using secret key ID_8
            System.out.println("Test decrypting ciphertext set 1 using secret key ID_8");
            assertEquals(false, stringSessionKeySet1.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            skNonReceiverID,
                            receiverSet1,
                            ciphertextSet1
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext set 4 using secret key ID_8
            System.out.println("Test decrypting ciphertext set 4 using secret key ID_8");
            assertEquals(false, stringSessionKeySet4.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            skNonReceiverID,
                            receiverSet4,
                            ciphertextSet4
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext set 8 using secret key ID_8
            System.out.println("Test decrypting ciphertext set 8 using secret key ID_8");
            assertEquals(false, stringSessionKeySet8.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            skNonReceiverID,
                            receiverSet8,
                            ciphertextSet8
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext set 9 using secret key ID_8, but the broadcast set is out of bound
            System.out.println("Test decrypting ciphertext set 9 using secret key ID_8, but the broadcast set is out of bound");
            PairingKeyEncapsulationSerPair ciphertextPairSet9 = engine.encapsulation(publicKey, receiverSet9);
            PairingCipherSerParameter ciphertextSet9 = ciphertextPairSet9.getCiphertext();
            byte[] sessionKeySet9 = ciphertextPairSet9.getSessionKey();
            String stringSessionKeySet9 = new String(Hex.encode(sessionKeySet9));
            assertEquals(false, stringSessionKeySet9.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            skNonReceiverID,
                            receiverSet9,
                            ciphertextSet9
                    )))
            ));
        } catch (Exception e) {
            //Correct if getting there, nothing to do
        }
        System.out.println("IBE engine functionality test passed.");
        System.out.println();
        //Test Serialize & deserialize
        System.out.println("======================================");
        System.out.println("Test IBE parameter serialization & de-serialization.");
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
            System.out.println("Test serialize & de-serialize secret key.");
            byte[] byteArraySkID01 = TestUtils.SerCipherParameter(skReceiverID);
            CipherParameters anSkID_1 = TestUtils.deserCipherParameters(byteArraySkID01);
            assertEquals(skReceiverID, anSkID_1);

            //serialize ciphertext01
            System.out.println("Test serialize & de-serialize ciphertext.");
            byte[] byteArrayCiphertext01 = TestUtils.SerCipherParameter(ciphertextSet1);
            CipherParameters anCiphertextID_1 = TestUtils.deserCipherParameters(byteArrayCiphertext01);
            assertEquals(ciphertextSet1, anCiphertextID_1);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("IBE parameter serialization tests passed.");
        System.out.println();
    }
}

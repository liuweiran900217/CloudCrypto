package com.example.encryption.ibbe;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.PairingParameterXMLSerializer;
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
 * Created by Weiran Liu on 2016/8/24.
 *
 * IBBE engine test procedures. All instances should pass this unit test.
 */
public class IBBEEngineTest {
    private IBBEEngine engine;
    private PairingParameterXMLSerializer schemeXMLSerializer;

    public IBBEEngineTest(IBBEEngine engine, PairingParameterXMLSerializer schemeXMLSerializer) {
        this.engine = engine;
        this.schemeXMLSerializer = schemeXMLSerializer;
    }

    public void processTest(int rBitLength, int qBitLength) {
        // Setup
        AsymmetricCipherKeyPair keyPair = engine.setup(rBitLength, qBitLength, 8);
        CipherParameters publicKey = keyPair.getPublic();
        CipherParameters masterKey = keyPair.getPrivate();
        PairingParameters pairingParameters = ((PairingKeySerParameter) publicKey).getParameters();

        // KeyGen
        String receiverID = "ID_0";
        String nonReceiverID = "ID_8";

        String[] receiverSet1 = {"ID_0"};
        String[] receiverSet4 = {"ID_2", "ID_3", "ID_1", "ID_0"};
        String[] receiverSet8 = {"ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0"};
        String[] receiverSet9 = {"ID_1", "ID_2", "ID_3", "ID_4", "ID_5", "ID_6", "ID_7", "ID_0", "ID_8"};

        CipherParameters skReceiverID = engine.keyGen(publicKey, masterKey, receiverID);
        CipherParameters skNonReceiverID = engine.keyGen(publicKey, masterKey, nonReceiverID);

        // Encryption
        PairingKeyEncapsulationSerPair ciphertextPairSet1 = engine.encapsulation(publicKey, receiverSet1);
        CipherParameters ciphertextSet1 = ciphertextPairSet1.getCiphertext();
        byte[] sessionKeySet1 = ciphertextPairSet1.getSessionKey();
        String stringSessionKeySet1 = new String(Hex.encode(sessionKeySet1));

        PairingKeyEncapsulationSerPair ciphertextPairSet4 = engine.encapsulation(publicKey, receiverSet4);
        CipherParameters ciphertextSet4 = ciphertextPairSet4.getCiphertext();
        byte[] sessionKeySet4 = ciphertextPairSet4.getSessionKey();
        String stringSessionKeySet4 = new String(Hex.encode(sessionKeySet4));

        PairingKeyEncapsulationSerPair ciphertextPairSet8 = engine.encapsulation(publicKey, receiverSet8);
        CipherParameters ciphertextSet8 = ciphertextPairSet8.getCiphertext();
        byte[] sessionKeySet8 = ciphertextPairSet8.getSessionKey();
        String stringSessionKeySet8 = new String(Hex.encode(sessionKeySet8));

        // Decrypt with correct secret keys
        System.out.println("========================================");
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
        System.out.println("==========================================");
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
            CipherParameters ciphertextSet9 = ciphertextPairSet9.getCiphertext();
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
        System.out.println("======================================");
        System.out.println("HIBBE Engine tests passed.");

        //Test Serialize & deserialize
        if (this.schemeXMLSerializer != null) {
            File file = new File("serializations/ibbe");
            file.mkdir();

            //Serialize & deserialize public key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing public key");
            TestUtils.OutputXMLDocument("serializations/ibbe/IBBE_Public_Key.xml", schemeXMLSerializer.documentSerialization(publicKey));
            Document documentPublicKey = TestUtils.InputXMLDocument("serializations/ibbe/IBBE_Public_Key.xml");
            CipherParameters anoPublicKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentPublicKey);
            assertEquals(publicKey, anoPublicKey);

            //Serialize & deserialize master secret key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing master secret key");
            TestUtils.OutputXMLDocument("serializations/ibbe/IBBE_Master_Secret_Key.xml", schemeXMLSerializer.documentSerialization(masterKey));
            Document documentMasterKey = TestUtils.InputXMLDocument("serializations/ibbe/IBBE_Master_Secret_Key.xml");
            CipherParameters anoMasterKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentMasterKey);
            assertEquals(masterKey, anoMasterKey);

            //Serialize & deserialize secret keys
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key for the receiver");
            //Serialize & deserialize secret key for the receiver
            TestUtils.OutputXMLDocument("serializations/ibbe/IBBE_Secret_Key_Receiver.xml", schemeXMLSerializer.documentSerialization(skReceiverID));
            Document documentSkReceiver = TestUtils.InputXMLDocument("serializations/ibbe/IBBE_Secret_Key_Receiver.xml");
            CipherParameters anSkReceiver = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSkReceiver);
            assertEquals(skReceiverID, anSkReceiver);
            //Serialize & deserialize secret key for the non-receiver
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key for the non-receiver");
            TestUtils.OutputXMLDocument("serializations/ibbe/IBBE_Secret_Key_NonReceiver.xml",schemeXMLSerializer.documentSerialization(skNonReceiverID));
            Document documentSkNonReceiver = TestUtils.InputXMLDocument("serializations/ibbe/IBBE_Secret_Key_NonReceiver.xml");
            CipherParameters anSkNonReceiver = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSkNonReceiver);
            assertEquals(skNonReceiverID, anSkNonReceiver);

            //Serialize & deserialize ciphertexts
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext set 1");
            //Serialize & deserialize ciphertext set 1
            TestUtils.OutputXMLDocument("serializations/ibbe/IBBE_Ciphertext_Set_1.xml", schemeXMLSerializer.documentSerialization(ciphertextSet1));
            Document documentCiphertextSet1 = TestUtils.InputXMLDocument("serializations/ibbe/IBBE_Ciphertext_Set_1.xml");
            CipherParameters anCiphertextSet1 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertextSet1);
            assertEquals(ciphertextSet1, anCiphertextSet1);
            //Serialize & deserialize ciphertext set 4
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext set 4");
            TestUtils.OutputXMLDocument("serializations/ibbe/IBBE_Ciphertext_Set_4.xml", schemeXMLSerializer.documentSerialization(ciphertextSet4));
            Document documentCiphertextSet4 = TestUtils.InputXMLDocument("serializations/ibbe/IBBE_Ciphertext_Set_4.xml");
            CipherParameters anCiphertextSet4 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertextSet4);
            assertEquals(ciphertextSet4, anCiphertextSet4);
            //Serialize & deserialize ciphertext set 8
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext set 8");
            TestUtils.OutputXMLDocument("serializations/ibbe/IBBE_Ciphertext_Set_8.xml", schemeXMLSerializer.documentSerialization(ciphertextSet8));
            Document documentCiphertextSet8 = TestUtils.InputXMLDocument("serializations/ibbe/IBBE_Ciphertext_Set_8.xml");
            CipherParameters anCiphertextSet8 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertextSet8);
            assertEquals(ciphertextSet8, anCiphertextSet8);

            System.out.println("======================================");
            System.out.println("Serialize & deserialize tests passed.");
        }
    }
}

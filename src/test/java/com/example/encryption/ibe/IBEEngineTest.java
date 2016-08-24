package com.example.encryption.ibe;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
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
 */
public class IBEEngineTest {
    private IBEEngine engine;
    private PairingParameterXMLSerializer schemeXMLSerializer;

    public IBEEngineTest(IBEEngine engine, PairingParameterXMLSerializer schemeXMLSerializer) {
        this.engine = engine;
        this.schemeXMLSerializer = schemeXMLSerializer;
    }

    public void processTest(int rBitLength, int qBitLength) {
        // Setup
        AsymmetricCipherKeyPair keyPair = engine.setup(rBitLength, qBitLength);
        CipherParameters publicKey = keyPair.getPublic();
        CipherParameters masterKey = keyPair.getPrivate();
        PairingParameters pairingParameters = ((PairingKeyParameters)publicKey).getParameters();

        // KeyGen
        String id_1 = "ID_1";
        String id_2 = "ID_2";

        CipherParameters skID_1 = engine.keyGen(publicKey, masterKey, id_1);
        CipherParameters skID_2 = engine.keyGen(publicKey, masterKey, id_2);

        // Encryption
        PairingKeyEncapsulationPair ciphertextPairID_1 = engine.encapsulation(publicKey, id_1);
        CipherParameters ciphertextID_1 = ciphertextPairID_1.getCiphertext();
        byte[] sessionKeyID_1 = ciphertextPairID_1.getSessionKey();
        String stringSessionKey0 = new String(Hex.encode(sessionKeyID_1));

        // Decrypt with correct secret keys
        System.out.println("========================================");
        System.out.println("Test decrypting with correct secret keys");
        try {
            //Decrypt ciphertext ID_1 using secret key ID_1
            System.out.println("Test decrypting ciphertext ID_1 using secret key ID_1");
            String sessionKey =  new String(Hex.encode(engine.decapsulation(publicKey, skID_1, id_1, ciphertextID_1)));
            assertEquals(stringSessionKey0, sessionKey);
            System.out.println("Expect:" + stringSessionKey0 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }

        //Decrypt with incorrect secret keys
        System.out.println("==========================================");
        System.out.println("Test decrypting with incorrect secret keys");
        try {
            //Decrypt ciphertext ID_1 using secret key ID_2
            System.out.println("Test decrypting ciphertext ID_1 using secret key ID_2");
            assertEquals(false, stringSessionKey0.equals(new String(Hex.encode(engine.decapsulation(
                            publicKey, skID_2, id_1, ciphertextID_1)))));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }

        //Test Serialize & deserialize
        if (this.schemeXMLSerializer != null) {
            File file = new File("serializations/ibe");
            file.mkdir();

            //Serialize & deserialize public key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing public key");
            TestUtils.OutputXMLDocument("serializations/ibe/IBE_Public_Key.xml", schemeXMLSerializer.documentSerialization(publicKey));
            Document documentPublicKey = TestUtils.InputXMLDocument("serializations/ibe/IBE_Public_Key.xml");
            CipherParameters anoPublicKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentPublicKey);
            assertEquals(publicKey, anoPublicKey);

            //Serialize & deserialize master secret key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing master secret key");
            TestUtils.OutputXMLDocument("serializations/ibe/IBE_Master_Secret_Key.xml", schemeXMLSerializer.documentSerialization(masterKey));
            Document documentMasterKey = TestUtils.InputXMLDocument("serializations/ibe/IBE_Master_Secret_Key.xml");
            CipherParameters anoMasterKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentMasterKey);
            assertEquals(masterKey, anoMasterKey);


            //Serialize & deserialize secret key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key");
            TestUtils.OutputXMLDocument("serializations/ibe/IBE_Secret_Key.xml", schemeXMLSerializer.documentSerialization(skID_1));
            Document documentSk = TestUtils.InputXMLDocument("serializations/ibe/IBE_Secret_Key.xml");
            CipherParameters anSk = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSk);
            assertEquals(skID_1, anSk);

            //Serialize & deserialize ciphertext
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext");
            TestUtils.OutputXMLDocument("serializations/ibe/IBE_Ciphertext.xml", schemeXMLSerializer.documentSerialization(ciphertextID_1));
            Document documentCiphertext = TestUtils.InputXMLDocument("serializations/ibe/IBE_Ciphertext.xml");
            CipherParameters anCiphertext = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertext);
            assertEquals(ciphertextID_1, anCiphertext);

            System.out.println("======================================");
            System.out.println("Serialize & deserialize tests passed.");
        }
    }
}

package com.example.encryption.re;

import cn.edu.buaa.crypto.encryption.re.REEngine;
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
 * Created by Weiran Liu on 2016/4/4.
 */
public class REEngineTest {
    private REEngine engine;
    private PairingParameterXMLSerializer schemeXMLSerializer;

    public REEngineTest(REEngine engine, PairingParameterXMLSerializer schemeXMLSerializer) {
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
        String id = "Identity";
        String rid = "Revocated Identity";

        CipherParameters skId = engine.keyGen(publicKey, masterKey, id);
        CipherParameters skRid = engine.keyGen(publicKey, masterKey, rid);

        // Encryption
        String[] rids1 = new String[]{rid, "Id_1"};
        PairingKeyEncapsulationPair ciphertextPairRids1 = engine.encapsulation(publicKey, rids1);
        CipherParameters ciphertextRids1 = ciphertextPairRids1.getCiphertext();
        byte[] sessionKeyRids1 = ciphertextPairRids1.getSessionKey();
        String stringSessionKeyRids1 = new String(Hex.encode(sessionKeyRids1));

        String[] rids2 = new String[]{"Id_1", "Id_2", "Id_3", "Id_4", "Id_5", "Id_6", "Id_7", "Id_8", "Id_9", rid};
        PairingKeyEncapsulationPair ciphertextPairRids2 = engine.encapsulation(publicKey, rids2);
        CipherParameters ciphertextRids2 = ciphertextPairRids2.getCiphertext();
        byte[] sessionKeyRids2 = ciphertextPairRids2.getSessionKey();
        String stringSessionKeyRids2 = new String(Hex.encode(sessionKeyRids2));

        // Decrypt with correct secret keys
        System.out.println("========================================");
        System.out.println("Test decrypting with correct secret keys");
        try {
            //Decrypt ciphertext Rids1 using secret key id
            System.out.println("Test decrypting ciphertext rids1 using secret key id");
            String sessionKey =  new String(Hex.encode(engine.decapsulation(publicKey, skId, rids1, ciphertextRids1)));
            assertEquals(stringSessionKeyRids1, sessionKey);
            System.out.println("Expect:" + stringSessionKeyRids1 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext Rids2 using secret key id
            System.out.println("Test decrypting ciphertext rids2 using secret key id");
            String sessionKey = new String(Hex.encode(engine.decapsulation(publicKey, skId, rids2, ciphertextRids2)));
            assertEquals(stringSessionKeyRids2, sessionKey);
            System.out.println("Expect:" + stringSessionKeyRids2 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }

        //Decrypt with incorrect secret keys
        System.out.println("==========================================");
        System.out.println("Test decrypting with incorrect secret keys");
        try {
            //Decrypt ciphertext Rids1 using secret key rid
            System.out.println("Test decrypting ciphertext rids1 using secret key rid");
            assertEquals(false, stringSessionKeyRids1.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            skRid,
                            rids1,
                            ciphertextPairRids1.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext Rids2 using secret key rid
            System.out.println("Test decrypting ciphertext rids2 using secret key rid");
            assertEquals(false, stringSessionKeyRids2.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            skRid,
                            rids2,
                            ciphertextPairRids2.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }

        //Test Serialize & deserialize
        if (this.schemeXMLSerializer != null) {
            File file = new File("serializations/re");
            file.mkdir();

            //Serialize & deserialize public key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing public key");
            TestUtils.OutputXMLDocument("serializations/re/RE_Public_Key.xml", schemeXMLSerializer.documentSerialization(publicKey));
            Document documentPublicKey = TestUtils.InputXMLDocument("serializations/re/RE_Public_Key.xml");
            CipherParameters anoPublicKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentPublicKey);
            assertEquals(publicKey, anoPublicKey);

            //Serialize & deserialize master secret key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing master secret key");
            TestUtils.OutputXMLDocument("serializations/re/RE_Master_Secret_Key.xml", schemeXMLSerializer.documentSerialization(masterKey));
            Document documentMasterKey = TestUtils.InputXMLDocument("serializations/re/RE_Master_Secret_Key.xml");
            CipherParameters anoMasterKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentMasterKey);
            assertEquals(masterKey, anoMasterKey);


            //Serialize & deserialize secret keys
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key skId");
            //Serialize & deserialize skId
            TestUtils.OutputXMLDocument("serializations/re/RE_Secret_Key_Id.xml", schemeXMLSerializer.documentSerialization(skId));
            Document documentSkId = TestUtils.InputXMLDocument("serializations/re/RE_Secret_Key_Id.xml");
            CipherParameters anSkId = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSkId);
            assertEquals(skId, anSkId);
            //Serialize & deserialize skRid
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key skRid");
            TestUtils.OutputXMLDocument("serializations/re/RE_Secret_Key_Rid.xml",schemeXMLSerializer.documentSerialization(skRid));
            Document documentSkRid = TestUtils.InputXMLDocument("serializations/re/RE_Secret_Key_Rid.xml");
            CipherParameters anSkRid = schemeXMLSerializer.documentDeserialization(pairingParameters, documentSkRid);
            assertEquals(skRid, anSkRid);

            //Serialize & deserialize ciphertexts
            //Serialize & deserialize ciphertext0
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext Rids1");
            TestUtils.OutputXMLDocument("serializations/re/RE_Ciphertext_Rids1.xml", schemeXMLSerializer.documentSerialization(ciphertextRids1));
            Document documentCiphertextRids1 = TestUtils.InputXMLDocument("serializations/re/RE_Ciphertext_Rids1.xml");
            CipherParameters anCiphertextRids1 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertextRids1);
            assertEquals(ciphertextRids1, anCiphertextRids1);
            //Serialize & deserialize ciphertext01
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing ciphertext Rids2");
            TestUtils.OutputXMLDocument("serializations/re/RE_Ciphertext_Rids2.xml", schemeXMLSerializer.documentSerialization(ciphertextRids2));
            Document documentCiphertextRids2 = TestUtils.InputXMLDocument("serializations/re/RE_Ciphertext_Rids2.xml");
            CipherParameters anCiphertextRids2 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentCiphertextRids2);
            assertEquals(ciphertextRids2, anCiphertextRids2);

            System.out.println("======================================");
            System.out.println("Serialize & deserialize tests passed.");
        }
    }
}

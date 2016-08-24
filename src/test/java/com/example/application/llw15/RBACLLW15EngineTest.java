package com.example.application.llw15;

import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import cn.edu.buaa.crypto.application.llw15.serialization.RBACLLW15XMLSerializer;
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
import static org.junit.Assert.assertFalse;

/**
 * Created by Weiran Liu on 16/6/19.
 */
public class RBACLLW15EngineTest {
    private RBACLLW15Engine engine;
    private PairingParameterXMLSerializer schemeXMLSerializer;

    public RBACLLW15EngineTest(RBACLLW15Engine engine, PairingParameterXMLSerializer schemeXMLSerializer) {
        this.engine = engine;
        this.schemeXMLSerializer = schemeXMLSerializer;
    }

    public void processTest(int rBitLength, int qBitLength) {
        // Setup
        AsymmetricCipherKeyPair keyPair = engine.Setup(rBitLength, qBitLength, 8);
        CipherParameters publicKey = keyPair.getPublic();
        CipherParameters masterKey = keyPair.getPrivate();
        PairingParameters pairingParameters = ((PairingKeyParameters)publicKey).getParameters();

        // Access Credential Generation for Medical Staff
        String[] role4    =    {null,      null,   null,       "Role_4",   null,       null,       null,       null};
        String[] role46   =    {null,      null,   null,       "Role_4",   null,       "Role_6",   null,       null};
        String[] role467  =    {null,      null,   null,       "Role_4",   null,       "Role_6",   "Role_7",   null};
        String[] role45   =    {null,      null,   null,       "Role_4",   "Role_5",   null,       null,       null};
        String[] role3    =    {"Role_3",  null,   null,       null,       null,       null,       null,       null};
        String[] role31   =    {"Role_3",  null,   "Role_1",   null,       null,       null,       null,       null};

        String timeT = "2016.06";
        String timeF = "2016.05";
        CipherParameters acMT4 = engine.ACGenM(publicKey, masterKey, role4, timeT);
        CipherParameters acMT46 = engine.ACGenM(publicKey, masterKey, role46, timeT);
        CipherParameters acMT467 = engine.ACGenM(publicKey, masterKey, role467, timeT);
        CipherParameters acMT45 = engine.ACGenM(publicKey, masterKey, role45, timeT);
        CipherParameters acMT3 = engine.ACGenM(publicKey, masterKey, role3, timeT);
        CipherParameters acMT31 = engine.ACGenM(publicKey, masterKey, role31, timeT);

        CipherParameters acMF4 = engine.ACGenM(publicKey, masterKey, role4, timeF);
        CipherParameters acMF46 = engine.ACGenM(publicKey, masterKey, role46, timeF);
        CipherParameters acMF467 = engine.ACGenM(publicKey, masterKey, role467, timeF);

        // Access Credential Generation for Patients
        String idT = "ID_T";
        String idF = "ID_F";

        CipherParameters acPT = engine.ACGenP(publicKey, masterKey, idT);
        CipherParameters acPF = engine.ACGenP(publicKey, masterKey, idF);

        String[] roles13467  = {"Role_1",  null,   "Role_3",   "Role_4",   null,       "Role_6",   "Role_7",   null};
        // Encryption
        PairingKeyEncapsulationPair encapsulationPair13467 = engine.EHREnc(publicKey, idT, roles13467, timeT);
        CipherParameters encapsulation13467 = encapsulationPair13467.getCiphertext();
        byte[] sessionKey13467 = encapsulationPair13467.getSessionKey();
        String stringSessionKey13467 = new String(Hex.encode(sessionKey13467));

        // Correct Decapsulation
        System.out.println("========================================");
        System.out.println("Test decapsulation with correct access credential, time, and identity");
        try {
            //Decapsulate using medical staff access credential 4 with true time
            System.out.println("Test decapsulating using medical staff access credential 4 with true time");
            String sessionKey =  new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMT4)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decapsulate using medical staff access credential 46 with true time
            System.out.println("Test decapsulating using medical staff access credential 46 with true time");
            String sessionKey =  new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMT46)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decapsulate using medical staff access credential 467 with true time
            System.out.println("Test decapsulating using medical staff access credential 467 with true time");
            String sessionKey =  new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMT467)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decapsulate using correct patient access credential
            System.out.println("Test decapsulating using correct patient access credential");
            String sessionKey =  new String(Hex.encode(engine.EHRDecP(publicKey, idT, roles13467, timeT, encapsulation13467, acPT)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }

        // Wrong Decapsulation
        System.out.println("==========================================");
        System.out.println("Test decapsulating with incorrect access credential, time, or identity");
        try {
            //Decapsulate using medical staff access credential 45 with true time
            System.out.println("Test decapsulating using medical staff access credential 45 with true time");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMT45)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }

        try {
            //Decapsulate using medical staff access credential 3 with true time
            System.out.println("Test decapsulating using medical staff access credential 3 with true time");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMT3)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decapsulate using medical staff access credential 31 with true time
            System.out.println("Test decapsulating using medical staff access credential 31 with true time");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMT31)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decapsulate using medical staff access credential 4 with wrong time
            System.out.println("Test decapsulating using medical staff access credential 4 with wrong time");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMF4)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decapsulate using medical staff access credential 46 with wrong time
            System.out.println("Test decapsulating using medical staff access credential 46 with wrong time");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMF46)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decapsulate using medical staff access credential 467 with wrong time
            System.out.println("Test decapsulating using medical staff access credential 467 with wrong time");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMF467)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decapsulate using correct patient access credential with wrong time
            System.out.println("Test decapsulating using incorrect patient access credential");
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecP(publicKey, idT, roles13467, timeT, encapsulation13467, acPF)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }


        //Delegate & Correct Decapsulate
        System.out.println("======================================");
        System.out.println("Test delegating and correct decapsulating");
        try {
            //Delegate medical staff access credential 46 using ac4 and decapsulating
            System.out.println("Test delegating medical staff access credential 46 using ac4 and decapsulating");
            String sessionKey = new String(Hex.encode(engine.EHRDecM(
                    publicKey, idT, roles13467, timeT, encapsulation13467, engine.ACDeleM(publicKey, acMT4, 5, "Role_6")
                    )));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Delegate medical staff access credential 467 using ac46 and decapsulating
            System.out.println("Test delegating medical staff access credential 467 using ac46 and decapsulating");
            String sessionKey = new String(Hex.encode(engine.EHRDecM(
                    publicKey, idT, roles13467, timeT, encapsulation13467, engine.ACDeleM(publicKey, acMT4, 6, "Role_7")
            )));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Delegate medical staff access credential 467 using ac4 and decapsulating
            System.out.println("Test delegating medical staff access credential 467 using ac4 and decapsulating");
            String sessionKey = new String(Hex.encode(engine.EHRDecM(
                    publicKey, idT, roles13467, timeT, encapsulation13467, engine.ACDeleM(publicKey,
                            engine.ACDeleM(publicKey, acMT4, 5, "Role_6"), 6, "Role_7")
            )));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        //Delegate & Incorrect Decapsulate
        System.out.println("========================================");
        System.out.println("Test delegating and incorrect decapsulating");
        try {
            System.out.println("Test delegating medical staff access credential 31 using ac3 and decapsulating");
            String sessionKey = new String(Hex.encode(engine.EHRDecM(
                    publicKey, idT, roles13467, timeT, encapsulation13467, engine.ACDeleM(publicKey, acMT3, 2, "ID_1")
            )));
            assertEquals(false, stringSessionKey13467.equals(sessionKey));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }

        // Encapsulation Audit
        System.out.println("========================================");
        System.out.println("Test Encapsulation Audit");
        //Encapsulation Audit with Wrong Time
        System.out.println("Test Encapsulation Audit with Wrong Time");
        assertFalse(engine.EHRAudit(publicKey, idT, roles13467, timeF, encapsulation13467));
        //Encapsulation Audit with Wrong Identity
        System.out.println("Test Encapsulation Audit with Wrong Identity");
        assertFalse(engine.EHRAudit(publicKey, idF, roles13467, timeT, encapsulation13467));
        //Encapsulation Audit with Wrong Roles
        System.out.println("Test Encapsulation Audit with Wrong Roles");
        assertFalse(engine.EHRAudit(publicKey, idF, role467, timeT, encapsulation13467));
        System.out.println("======================================");
        System.out.println("HIBBE Engine tests passed.");

        //Test Serialize & deserialize
        if (this.schemeXMLSerializer != null) {
            File file = new File("serializations/application/LLW15");
            file.mkdir();

            //Serialize & deserialize public key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing public key");
            TestUtils.OutputXMLDocument("serializations/application/LLW15/RBAC_Public_Key.xml", schemeXMLSerializer.documentSerialization(publicKey));
            Document documentPublicKey = TestUtils.InputXMLDocument("serializations/application/LLW15/RBAC_Public_Key.xml");
            CipherParameters anoPublicKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentPublicKey);
            assertEquals(publicKey, anoPublicKey);

            //Serialize & deserialize master secret key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing master secret key");
            TestUtils.OutputXMLDocument("serializations/application/LLW15/RBAC_Master_Secret_Key.xml", schemeXMLSerializer.documentSerialization(masterKey));
            Document documentMasterKey = TestUtils.InputXMLDocument("serializations/application/LLW15/RBAC_Master_Secret_Key.xml");
            CipherParameters anoMasterKey = schemeXMLSerializer.documentDeserialization(pairingParameters, documentMasterKey);
            assertEquals(masterKey, anoMasterKey);


            //Serialize & deserialize medical staff access credential
            //Serialize & deserialize acM4
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing medical staff access credential 4");
            TestUtils.OutputXMLDocument("serializations/application/LLW15/RBAC_Access_Credential_M4.xml", schemeXMLSerializer.documentSerialization(acMT4));
            Document documentACMT4 = TestUtils.InputXMLDocument("serializations/application/LLW15/RBAC_Access_Credential_M4.xml");
            CipherParameters anACMT4 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentACMT4);
            assertEquals(acMT4, anACMT4);
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing medical staff access credential 46");
            //Serialize & deserialize acM46
            TestUtils.OutputXMLDocument("serializations/application/LLW15/RBAC_Access_Credential_M46.xml", schemeXMLSerializer.documentSerialization(acMT46));
            Document documentACMT46 = TestUtils.InputXMLDocument("serializations/application/LLW15/RBAC_Access_Credential_M46.xml");
            CipherParameters anACMT46 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentACMT46);
            assertEquals(acMT46, anACMT46);
            //Serialize & deserialize acM467
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing medical staff access credential 467");
            TestUtils.OutputXMLDocument("serializations/application/LLW15/RBAC_Access_Credential_M467.xml", schemeXMLSerializer.documentSerialization(acMT467));
            Document documentACMT467 = TestUtils.InputXMLDocument("serializations/application/LLW15/RBAC_Access_Credential_M467.xml");
            CipherParameters anACMT467 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentACMT467);
            assertEquals(acMT467, anACMT467);

            //Serialize & deserialize patient access credential
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing patient access credential");
            TestUtils.OutputXMLDocument("serializations/application/LLW15/RBAC_Access_Credential_P.xml", schemeXMLSerializer.documentSerialization(acPT));
            Document documentACPT = TestUtils.InputXMLDocument("serializations/application/LLW15/RBAC_Access_Credential_P.xml");
            CipherParameters anACPT = schemeXMLSerializer.documentDeserialization(pairingParameters, documentACPT);
            assertEquals(acPT, anACPT);

            //Serialize & deserialize encapsulation
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing encapsulation 13467");
            TestUtils.OutputXMLDocument("serializations/application/LLW15/RBAC_Encapsulation_13467.xml", schemeXMLSerializer.documentSerialization(encapsulation13467));
            Document documentEncapsulation13467 = TestUtils.InputXMLDocument("serializations/application/LLW15/RBAC_Encapsulation_13467.xml");
            CipherParameters anEncapsulation13467 = schemeXMLSerializer.documentDeserialization(pairingParameters, documentEncapsulation13467);
            assertEquals(encapsulation13467, anEncapsulation13467);

            System.out.println("======================================");
            System.out.println("Serialize & deserialize tests passed.");
        }
    }

    public static void main(String[] args) {
        RBACLLW15Engine engine = new RBACLLW15Engine();
        PairingParameterXMLSerializer schemeXMLSerializer = RBACLLW15XMLSerializer.getInstance();

        RBACLLW15EngineTest engineTest = new RBACLLW15EngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(160, 256);
    }
}

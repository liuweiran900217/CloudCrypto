package com.example.application.llw15;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

/**
 * Created by Weiran Liu on 16/6/19.
 *
 * Liu-Liu-Wu EHR role-based access control engine test.
 */
public class RBACLLW15EngineTest {
    private RBACLLW15Engine engine;

    private RBACLLW15EngineTest(RBACLLW15Engine engine) {
        this.engine = engine;
    }

    public void processTest(PairingParameters pairingParameters) {
        // Setup
        AsymmetricKeySerPair keyPair = engine.Setup(pairingParameters, 8);
        AsymmetricKeySerParameter publicKey = keyPair.getPublic();
        AsymmetricKeySerParameter masterKey = keyPair.getPrivate();

        // Access Credential Generation for Medical Staff
        String[] role4    =    {null,      null,   null,       "Role_4",   null,       null,       null,       null};
        String[] role46   =    {null,      null,   null,       "Role_4",   null,       "Role_6",   null,       null};
        String[] role467  =    {null,      null,   null,       "Role_4",   null,       "Role_6",   "Role_7",   null};
        String[] role45   =    {null,      null,   null,       "Role_4",   "Role_5",   null,       null,       null};
        String[] role3    =    {"Role_3",  null,   null,       null,       null,       null,       null,       null};
        String[] role31   =    {"Role_3",  null,   "Role_1",   null,       null,       null,       null,       null};

        String timeT = "2016.06";
        String timeF = "2016.05";
        AsymmetricKeySerParameter acMT4 = engine.ACGenM(publicKey, masterKey, role4, timeT);
        AsymmetricKeySerParameter acMT46 = engine.ACGenM(publicKey, masterKey, role46, timeT);
        AsymmetricKeySerParameter acMT467 = engine.ACGenM(publicKey, masterKey, role467, timeT);
        AsymmetricKeySerParameter acMT45 = engine.ACGenM(publicKey, masterKey, role45, timeT);
        AsymmetricKeySerParameter acMT3 = engine.ACGenM(publicKey, masterKey, role3, timeT);
        AsymmetricKeySerParameter acMT31 = engine.ACGenM(publicKey, masterKey, role31, timeT);

        AsymmetricKeySerParameter acMF4 = engine.ACGenM(publicKey, masterKey, role4, timeF);
        AsymmetricKeySerParameter acMF46 = engine.ACGenM(publicKey, masterKey, role46, timeF);
        AsymmetricKeySerParameter acMF467 = engine.ACGenM(publicKey, masterKey, role467, timeF);

        // Access Credential Generation for Patients
        String idT = "ID_T";
        String idF = "ID_F";

        AsymmetricKeySerParameter acPT = engine.ACGenP(publicKey, masterKey, idT);
        AsymmetricKeySerParameter acPF = engine.ACGenP(publicKey, masterKey, idF);

        String[] roles13467  = {"Role_1",  null,   "Role_3",   "Role_4",   null,       "Role_6",   "Role_7",   null};
        // Encryption
        PairingKeyEncapsulationSerPair encapsulationPair13467 = engine.EHREnc(publicKey, idT, roles13467, timeT);
        PairingCipherSerParameter encapsulation13467 = encapsulationPair13467.getCiphertext();
        byte[] sessionKey13467 = encapsulationPair13467.getSessionKey();
        String stringSessionKey13467 = new String(Hex.encode(sessionKey13467));

        System.out.println("========================================");
        System.out.println("Test Liu-Liu-Wu EHR RBAC functionality");
        // Correct Decapsulation
        System.out.println("Test decapsulation with correct access credential, time, and identity");
        try {
            //Decapsulate using medical staff access credential 4 with true time
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
        System.out.println("Test decapsulating with incorrect access credential, time, or identity");
        try {
            //Decapsulate using medical staff access credential 45 with true time
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMT45)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }

        try {
            //Decapsulate using medical staff access credential 3 with true time
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMT3)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decapsulate using medical staff access credential 31 with true time
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMT31)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decapsulate using medical staff access credential 4 with wrong time
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMF4)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decapsulate using medical staff access credential 46 with wrong time
            assertEquals(false, stringSessionKey13467.equals(
                    new String(Hex.encode(engine.EHRDecM(publicKey, idT, roles13467, timeT, encapsulation13467, acMF46)))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decapsulate using medical staff access credential 467 with wrong time
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
        System.out.println("Test delegating and correct decapsulating");
        try {
            //Delegate medical staff access credential 46 using ac4 and decapsulating
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
        System.out.println("Test delegating and incorrect decapsulating");
        try {
            String sessionKey = new String(Hex.encode(engine.EHRDecM(
                    publicKey, idT, roles13467, timeT, encapsulation13467, engine.ACDeleM(publicKey, acMT3, 2, "ID_1")
            )));
            assertEquals(false, stringSessionKey13467.equals(sessionKey));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }

        // Encapsulation Audit
        System.out.println("Test Encapsulation Audit");
        //Encapsulation Audit with Wrong Time
        assertFalse(engine.EHRAudit(publicKey, idT, roles13467, timeF, encapsulation13467));
        //Encapsulation Audit with Wrong Identity
        assertFalse(engine.EHRAudit(publicKey, idF, roles13467, timeT, encapsulation13467));
        //Encapsulation Audit with Wrong Roles
        assertFalse(engine.EHRAudit(publicKey, idF, role467, timeT, encapsulation13467));

        //ACGenM using intermediate parameters
        PairingCipherSerParameter acMT4IntermediateParameters = engine.IntermediateGen(publicKey);
        acMT4 = engine.ACGenM(publicKey, masterKey, acMT4IntermediateParameters, role4, timeT);
        PairingCipherSerParameter acMT46IntermediateParameters = engine.IntermediateGen(publicKey);
        acMT46 = engine.ACGenM(publicKey, masterKey, acMT46IntermediateParameters, role46, timeT);
        PairingCipherSerParameter acMT467IntermediateParameters = engine.IntermediateGen(publicKey);
        acMT467 = engine.ACGenM(publicKey, masterKey, acMT467IntermediateParameters, role467, timeT);

        // ACGenP for Patients with intermediate parameters
        PairingCipherSerParameter acPTIntermediateParameters = engine.IntermediateGen(publicKey);
        acPT = engine.ACGenP(publicKey, masterKey, acPTIntermediateParameters, idT);

        // Encryption with intermediate parameters
        PairingCipherSerParameter encapsulationPair3467IntermediateParameters = engine.IntermediateGen(publicKey);
        encapsulationPair13467 = engine.EHREnc(publicKey, encapsulationPair3467IntermediateParameters, idT, roles13467, timeT);
        encapsulation13467 = encapsulationPair13467.getCiphertext();
        sessionKey13467 = encapsulationPair13467.getSessionKey();
        stringSessionKey13467 = new String(Hex.encode(sessionKey13467));

        // Correct Decapsulation with intermediate parameters
        System.out.println("Test decapsulation with correct access credential, time, and identity, " +
                "parameters are generated using intermediate parameters");
        try {
            //Decapsulate using medical staff access credential 4 with true time
            String sessionKey =  new String(Hex.encode(engine.EHRDecMWithAudit(publicKey, idT, roles13467, timeT, encapsulation13467, acMT4)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decapsulate using medical staff access credential 46 with true time
            String sessionKey =  new String(Hex.encode(engine.EHRDecMWithAudit(publicKey, idT, roles13467, timeT, encapsulation13467, acMT46)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decapsulate using medical staff access credential 467 with true time
            String sessionKey =  new String(Hex.encode(engine.EHRDecMWithAudit(publicKey, idT, roles13467, timeT, encapsulation13467, acMT467)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decapsulate using correct patient access credential
            System.out.println("Test decapsulating using correct patient access credential, " +
                    "parameters are generated using intermediate parameters");
            String sessionKey =  new String(Hex.encode(engine.EHRDecPWithAudit(publicKey, idT, roles13467, timeT, encapsulation13467, acPT)));
            assertEquals(stringSessionKey13467, sessionKey);
            System.out.println("Expect:" + stringSessionKey13467 + "\nActual:" + sessionKey);
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }

        //Delegate & Correct Decapsulate
        System.out.println("Test delegating and correct decapsulating, " +
                "parameters are generated using intermediate parameters");
        try {
            //Delegate medical staff access credential 46 using ac4 and decapsulating
            PairingCipherSerParameter acMT45DelegateIntermediateParameters = engine.IntermediateGen(publicKey);
            String sessionKey = new String(Hex.encode(engine.EHRDecMWithAudit(
                    publicKey, idT, roles13467, timeT, encapsulation13467, engine.ACDeleM(publicKey, acMT4, acMT45DelegateIntermediateParameters, 5, "Role_6")
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
            PairingCipherSerParameter acMT46DelegateIntermediateParameters = engine.IntermediateGen(publicKey);
            String sessionKey = new String(Hex.encode(engine.EHRDecMWithAudit(
                    publicKey, idT, roles13467, timeT, encapsulation13467, engine.ACDeleM(publicKey, acMT4, acMT46DelegateIntermediateParameters, 6, "Role_7")
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
            String sessionKey = new String(Hex.encode(engine.EHRDecMWithAudit(
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
        System.out.println("HIBBE Engine functionality test passed.");
        System.out.println();

        //Test Serialize & deserialize
        System.out.println("======================================");
        System.out.println("Test Liu-Liu-Wu EHR RBAC parameter serialize * de-serialize");
        try {
            //Serialize & deserialize public key
            System.out.println("Test serialize & de-serialize public key");
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            assertEquals(publicKey, anPublicKey);

            //serialize master secret key
            System.out.println("Test serialize & de-serialize master secret key.");
            byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
            CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
            assertEquals(masterKey, anMasterKey);

            //serialize medical staff access credential
            System.out.println("Test serialize & de-serialize medical staff access credentials.");
            //serialize acM4
            byte[] byteArrayAcMT4 = TestUtils.SerCipherParameter(acMT4);
            CipherParameters anAcMT4 = TestUtils.deserCipherParameters(byteArrayAcMT4);
            assertEquals(acMT4, anAcMT4);
            //serialize acM46
            byte[] byteArrayAcMT46 = TestUtils.SerCipherParameter(acMT46);
            CipherParameters anAcMT46 = TestUtils.deserCipherParameters(byteArrayAcMT46);
            assertEquals(acMT46, anAcMT46);
            //serialize acM467
            byte[] byteArrayAcMT467 = TestUtils.SerCipherParameter(acMT467);
            CipherParameters anAcMT467 = TestUtils.deserCipherParameters(byteArrayAcMT467);
            assertEquals(acMT467, anAcMT467);

            //serialize patient access credential
            System.out.println("Test serialize & de-serialize patient access credential.");
            //serialize acPT
            byte[] byteArrayAcPT = TestUtils.SerCipherParameter(acPT);
            CipherParameters anAcPT = TestUtils.deserCipherParameters(byteArrayAcPT);
            assertEquals(acPT, anAcPT);

            //serialize encapsulation
            System.out.println("Test serialize & de-serialize encapsulations.");
            byte[] byteArrayEncapsulation13467 = TestUtils.SerCipherParameter(encapsulation13467);
            CipherParameters anEncapsulation13467 = TestUtils.deserCipherParameters(byteArrayEncapsulation13467);
            assertEquals(encapsulation13467, anEncapsulation13467);

            //serialize intermediate parameters
            System.out.println("Test serialize & de-serialize intermediate parameters.");
            CipherParameters intermediateParameter = engine.IntermediateGen(publicKey);
            byte[] byteArrayIntermediate = TestUtils.SerCipherParameter(intermediateParameter);
            CipherParameters anIntermediateParameter = TestUtils.deserCipherParameters(byteArrayIntermediate);
            assertEquals(intermediateParameter, anIntermediateParameter);
            System.out.println("Liu-Liu-Wu EHR RBAC parameter serialization test passed.");
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static void main(String[] args) {
        RBACLLW15Engine engine = RBACLLW15Engine.getInstance();
        RBACLLW15EngineTest engineTest = new RBACLLW15EngineTest(engine);

        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
        engineTest.processTest(pairingParameters);
    }
}

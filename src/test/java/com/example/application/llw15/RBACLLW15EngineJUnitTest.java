package com.example.application.llw15;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/6/19.
 *
 * Liu-Liu-Wu EHR role-based access control engine test.
 */

public class RBACLLW15EngineJUnitTest extends TestCase {
    // Access Credential Generation for Medical Staff
    private static final String[] role4    =    {null,      null,   null,       "Role_4",   null,       null,       null,       null};
    private static final String[] role46   =    {null,      null,   null,       "Role_4",   null,       "Role_6",   null,       null};
    private static final String[] role467  =    {null,      null,   null,       "Role_4",   null,       "Role_6",   "Role_7",   null};
    private static final String[] role45   =    {null,      null,   null,       "Role_4",   "Role_5",   null,       null,       null};
    private static final String[] role3    =    {"Role_3",  null,   null,       null,       null,       null,       null,       null};
    private static final String[] role31   =    {"Role_3",  null,   "Role_1",   null,       null,       null,       null,       null};

    private static final String timeT = "2016.06";
    private static final String timeF = "2016.05";

    // Access Credential Generation for Patients
    private static final String idT = "ID_T";
    private static final String idF = "ID_F";

    private static final String[] roles13467  = {"Role_1",  null,   "Role_3",   "Role_4",   null,       "Role_6",   "Role_7",   null};

    private RBACLLW15Engine engine;

    private void try_patient_valid_decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String identity, String[] roles, String encIdentity, String encTime) {
        try {
            try_patient_decapsulation(publicKey, masterKey, identity, roles, encIdentity, encTime);
        } catch (Exception e) {
            System.out.println("Valid patient decapsulation test failed, " +
                    "patient identity    = " + identity + ", " +
                    "encapsulation roles = " + Arrays.toString(roles) + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
        try {
            try_patient_decapsulation_with_intermediate(publicKey, masterKey, identity, roles, encIdentity, encTime);
        } catch (Exception e) {
            System.out.println("Valid patient decapsulation test with intermediate failed, " +
                    "patient identity    = " + identity + ", " +
                    "encapsulation roles = " + Arrays.toString(roles) + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_patient_invalid_decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String identity, String[] roles, String encIdentity, String encTime) {
        try {
            try_patient_decapsulation(publicKey, masterKey, identity, roles, encIdentity, encTime);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid patient decapsulation test failed, " +
                    "patient identity    = " + identity + ", " +
                    "encapsulation roles = " + Arrays.toString(roles) + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
        try {
            try_patient_decapsulation_with_intermediate(publicKey, masterKey, identity, roles, encIdentity, encTime);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid patient decapsulation with intermediate test failed, " +
                    "patient identity    = " + identity + ", " +
                    "encapsulation roles = " + Arrays.toString(roles) + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_patient_decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String identity, String[] roles, String encIdentity, String encTime)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter accessCredentialP = engine.ACGenP(publicKey, masterKey, identity);
        byte[] byteArrayAccessCredentialP = TestUtils.SerCipherParameter(accessCredentialP);
        CipherParameters anAccessCredentialP = TestUtils.deserCipherParameters(byteArrayAccessCredentialP);
        Assert.assertEquals(accessCredentialP, anAccessCredentialP);
        accessCredentialP = (PairingKeySerParameter)anAccessCredentialP;

        //encapsulation and serialization without intermediate ciphertext
        PairingKeyEncapsulationSerPair encapsulationSerPair = engine.EHREnc(publicKey, encIdentity, roles, encTime);
        byte[] sessionKey = encapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = encapsulationSerPair.getHeader();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.EHRDecPWithAudit(publicKey, encIdentity, roles, encTime, ciphertext, accessCredentialP);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void try_patient_decapsulation_with_intermediate(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String identity, String[] roles, String encIdentity, String encTime)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //generate intermediate
        PairingCipherSerParameter intermediateParameter = engine.IntermediateGen(publicKey);
        byte[] byteArrayIntermediateParameter = TestUtils.SerCipherParameter(intermediateParameter);
        CipherParameters anIntermediateParameter = TestUtils.deserCipherParameters(byteArrayIntermediateParameter);
        intermediateParameter = (PairingCipherSerParameter)anIntermediateParameter;

        //KeyGen and serialization
        PairingKeySerParameter accessCredentialP = engine.ACGenP(publicKey, masterKey, intermediateParameter, identity);
        byte[] byteArrayAccessCredentialP = TestUtils.SerCipherParameter(accessCredentialP);
        CipherParameters anAccessCredentialP = TestUtils.deserCipherParameters(byteArrayAccessCredentialP);
        Assert.assertEquals(accessCredentialP, anAccessCredentialP);
        accessCredentialP = (PairingKeySerParameter)anAccessCredentialP;

        //encapsulation and serialization without intermediate ciphertext
        PairingKeyEncapsulationSerPair encapsulationSerPair = engine.EHREnc(publicKey, intermediateParameter, encIdentity, roles, encTime);
        byte[] sessionKey = encapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = encapsulationSerPair.getHeader();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.EHRDecPWithAudit(publicKey, encIdentity, roles, encTime, ciphertext, accessCredentialP);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void try_medical_valid_decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String[] medicalRoles, String medicalTime, String[] roles, String encIdentity, String encTime) {
        try {
            try_medical_decapsulation(publicKey, masterKey, medicalRoles, medicalTime, roles, encIdentity, encTime);
        } catch (Exception e) {
            System.out.println("Valid medical staff decapsulation test failed, " +
                    "medical staff roles = " + Arrays.toString(medicalRoles) + ", " +
                    "medical staff time  = " + medicalTime + ", " +
                    "encapsulation roles = " + Arrays.toString(roles) + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
        try {
            try_medical_decapsulation_with_intermediate(publicKey, masterKey, medicalRoles, medicalTime, roles, encIdentity, encTime);
        } catch (Exception e) {
            System.out.println("Valid medical staff decapsulation with intermediate test failed, " +
                    "medical staff roles = " + Arrays.toString(medicalRoles) + ", " +
                    "medical staff time  = " + medicalTime + ", " +
                    "encapsulation roles = " + Arrays.toString(roles) + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_medical_invalid_decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String[] medicalRoles, String medicalTime, String[] roles, String encIdentity, String encTime) {
        try {
            try_medical_decapsulation(publicKey, masterKey, medicalRoles, medicalTime, roles, encIdentity, encTime);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid medical staff decapsulation test failed, " +
                    "medical staff roles = " + Arrays.toString(medicalRoles) + ", " +
                    "medical staff time  = " + medicalTime + ", " +
                    "encapsulation roles = " + Arrays.toString(roles) + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
        try {
            try_medical_decapsulation_with_intermediate(publicKey, masterKey, medicalRoles, medicalTime, roles, encIdentity, encTime);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid medical staff decapsulation with intermediate test failed, " +
                    "medical staff roles = " + Arrays.toString(medicalRoles) + ", " +
                    "medical staff time  = " + medicalTime + ", " +
                    "encapsulation roles = " + Arrays.toString(roles) + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_medical_decapsulation(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String[] medicalRoles, String medicalTime, String[] roles, String encIdentity, String encTime)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //KeyGen and serialization
        PairingKeySerParameter accessCredentialM = engine.ACGenM(publicKey, masterKey, medicalRoles, medicalTime);
        byte[] byteArrayAccessCredentialM = TestUtils.SerCipherParameter(accessCredentialM);
        CipherParameters anAccessCredentialM = TestUtils.deserCipherParameters(byteArrayAccessCredentialM);
        Assert.assertEquals(accessCredentialM, anAccessCredentialM);
        accessCredentialM = (PairingKeySerParameter)anAccessCredentialM;

        //encapsulation and serialization without intermediate ciphertext
        PairingKeyEncapsulationSerPair encapsulationSerPair = engine.EHREnc(publicKey, encIdentity, roles, encTime);
        byte[] sessionKey = encapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = encapsulationSerPair.getHeader();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.EHRDecMWithAudit(publicKey, encIdentity, roles, encTime, ciphertext, accessCredentialM);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void try_medical_decapsulation_with_intermediate(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String[] medicalRoles, String medicalTime, String[] roles, String encIdentity, String encTime)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //generate intermediate
        PairingCipherSerParameter intermediateParameter = engine.IntermediateGen(publicKey);
        byte[] byteArrayIntermediateParameter = TestUtils.SerCipherParameter(intermediateParameter);
        CipherParameters anIntermediateParameter = TestUtils.deserCipherParameters(byteArrayIntermediateParameter);
        intermediateParameter = (PairingCipherSerParameter)anIntermediateParameter;

        //KeyGen and serialization
        PairingKeySerParameter accessCredentialM = engine.ACGenM(publicKey, masterKey, intermediateParameter, medicalRoles, medicalTime);
        byte[] byteArrayAccessCredentialM = TestUtils.SerCipherParameter(accessCredentialM);
        CipherParameters anAccessCredentialM = TestUtils.deserCipherParameters(byteArrayAccessCredentialM);
        Assert.assertEquals(accessCredentialM, anAccessCredentialM);
        accessCredentialM = (PairingKeySerParameter)anAccessCredentialM;

        //encapsulation and serialization without intermediate ciphertext
        PairingKeyEncapsulationSerPair encapsulationSerPair = engine.EHREnc(publicKey, intermediateParameter, encIdentity, roles, encTime);
        byte[] sessionKey = encapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = encapsulationSerPair.getHeader();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.EHRDecMWithAudit(publicKey, encIdentity, roles, encTime, ciphertext, accessCredentialM);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void try_medical_valid_delegation(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String[] medicalRoles, String medicalTime, int index, String role, String[] roles, String encIdentity, String encTime) {
        try {
            try_medical_delegation(publicKey, masterKey, medicalRoles, medicalTime, index, role, roles, encIdentity, encTime);
        } catch (Exception e) {
            System.out.println("Valid medical staff decapsulation test failed, " +
                    "medical staff roles = " + Arrays.toString(medicalRoles) + ", " +
                    "medical staff time  = " + medicalTime + ", " +
                    "delegation index    = " + index + ", " +
                    "delegation role     = " + role + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
        try {
            try_medical_delegation_with_intermediate(publicKey, masterKey, medicalRoles, medicalTime, index, role, roles, encIdentity, encTime);
        } catch (Exception e) {
            System.out.println("Valid medical staff decapsulation with intermediate test failed, " +
                    "medical staff roles = " + Arrays.toString(medicalRoles) + ", " +
                    "medical staff time  = " + medicalTime + ", " +
                    "delegation index    = " + index + ", " +
                    "delegation role     = " + role + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_medical_invalid_delegation(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String[] medicalRoles, String medicalTime, int index, String[] roles, String encIdentity, String encTime) {
        try {
            try_medical_delegation(publicKey, masterKey, medicalRoles, medicalTime, index, "Role_1", roles, encIdentity, encTime);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid medical staff decapsulation test failed, " +
                    "medical staff roles = " + Arrays.toString(medicalRoles) + ", " +
                    "medical staff time  = " + medicalTime + ", " +
                    "delegation index    = " + index + ", " +
                    "delegation role     = " + "Role_1" + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
        try {
            try_medical_delegation_with_intermediate(publicKey, masterKey, medicalRoles, medicalTime, index, "Role_1", roles, encIdentity, encTime);
        } catch (InvalidCipherTextException e) {
            //correct if getting there, nothing to do.
        } catch (Exception e) {
            System.out.println("Invalid medical staff decapsulation with intermediate test failed, " +
                    "medical staff roles = " + Arrays.toString(medicalRoles) + ", " +
                    "medical staff time  = " + medicalTime + ", " +
                    "delegation index    = " + index + ", " +
                    "delegation role     = " + "Role_1" + ", " +
                    "encapsulation id.   = " + encIdentity + ", " +
                    "encapsulation time  = " + encTime);
            e.printStackTrace();
            System.exit(1);
        }
    }

    private void try_medical_delegation(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String[] medicalRoles, String medicalTime, int index, String role, String[] roles, String encIdentity, String encTime)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //Delegation and serialization
        PairingKeySerParameter accessCredentialM = engine.ACGenM(publicKey, masterKey, medicalRoles, medicalTime);
        PairingKeySerParameter accessCredentialDeleM = engine.ACDeleM(publicKey, accessCredentialM, index, role);

        byte[] byteArrayAccessCredentialDeleM = TestUtils.SerCipherParameter(accessCredentialDeleM);
        CipherParameters anAccessCredentialDeleM = TestUtils.deserCipherParameters(byteArrayAccessCredentialDeleM);
        Assert.assertEquals(accessCredentialDeleM, anAccessCredentialDeleM);
        accessCredentialDeleM = (PairingKeySerParameter)anAccessCredentialDeleM;

        //encapsulation and serialization without intermediate ciphertext
        PairingKeyEncapsulationSerPair encapsulationSerPair = engine.EHREnc(publicKey, encIdentity, roles, encTime);
        byte[] sessionKey = encapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = encapsulationSerPair.getHeader();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.EHRDecMWithAudit(publicKey, encIdentity, roles, encTime, ciphertext, accessCredentialDeleM);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void try_medical_delegation_with_intermediate(
            PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
            String[] medicalRoles, String medicalTime, int index, String role, String[] roles, String encIdentity, String encTime)
            throws InvalidCipherTextException, IOException, ClassNotFoundException {
        //generate intermediate
        PairingCipherSerParameter intermediateParameter = engine.IntermediateGen(publicKey);
        byte[] byteArrayIntermediateParameter = TestUtils.SerCipherParameter(intermediateParameter);
        CipherParameters anIntermediateParameter = TestUtils.deserCipherParameters(byteArrayIntermediateParameter);
        intermediateParameter = (PairingCipherSerParameter)anIntermediateParameter;

        //Delegation and serialization
        PairingKeySerParameter accessCredentialM = engine.ACGenM(publicKey, masterKey, medicalRoles, medicalTime);
        PairingKeySerParameter accessCredentialDeleM = engine.ACDeleM(publicKey, accessCredentialM, intermediateParameter, index, role);

        byte[] byteArrayAccessCredentialDeleM = TestUtils.SerCipherParameter(accessCredentialDeleM);
        CipherParameters anAccessCredentialDeleM = TestUtils.deserCipherParameters(byteArrayAccessCredentialDeleM);
        Assert.assertEquals(accessCredentialDeleM, anAccessCredentialDeleM);
        accessCredentialDeleM = (PairingKeySerParameter)anAccessCredentialDeleM;

        //encapsulation and serialization without intermediate ciphertext
        PairingKeyEncapsulationSerPair encapsulationSerPair = engine.EHREnc(publicKey, intermediateParameter, encIdentity, roles, encTime);
        byte[] sessionKey = encapsulationSerPair.getSessionKey();
        PairingCipherSerParameter ciphertext = encapsulationSerPair.getHeader();
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter)anCiphertext;

        //Decryption
        byte[] anSessionKey = engine.EHRDecMWithAudit(publicKey, encIdentity, roles, encTime, ciphertext, accessCredentialDeleM);
        Assert.assertArrayEquals(sessionKey, anSessionKey);
    }

    private void try_invalid_audit(PairingKeySerParameter publicKey, String[] roles, String identity, String time,
                                   String[] encRoles, String encIdentity, String encTime) {
        PairingKeyEncapsulationSerPair encapsulationSerPair = engine.EHREnc(publicKey, encIdentity, encRoles, encTime);
        Assert.assertFalse(engine.EHRAudit(publicKey, identity, roles, time, encapsulationSerPair.getHeader()));
    }

    private void runAllTests(PairingParameters pairingParameters) {
        try {
            // Setup and serialization
            PairingKeySerPair keyPair = engine.Setup(pairingParameters, roles13467.length);
            PairingKeySerParameter publicKey = keyPair.getPublic();
            byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            Assert.assertEquals(publicKey, anPublicKey);
            publicKey = (PairingKeySerParameter) anPublicKey;

            PairingKeySerParameter masterKey = keyPair.getPrivate();
            byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
            CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
            Assert.assertEquals(masterKey, anMasterKey);
            masterKey = (PairingKeySerParameter) anMasterKey;

            //test valid example
            System.out.println("Test valid examples");
            try_patient_valid_decapsulation(publicKey, masterKey, idT, roles13467, idT, timeT);
            try_medical_valid_decapsulation(publicKey, masterKey, role4, timeT, roles13467, idT, timeT);
            try_medical_valid_decapsulation(publicKey, masterKey, role46, timeT, roles13467, idT, timeT);
            try_medical_valid_decapsulation(publicKey, masterKey, role467, timeT, roles13467, idT, timeT);
            try_medical_valid_delegation(publicKey, masterKey, role4, timeT, 5, "Role_6", roles13467, idT, timeT);
            try_medical_valid_delegation(publicKey, masterKey, role46, timeT, 6, "Role_7", roles13467, idT, timeT);

            //test valid example
            System.out.println("Test invalid examples");
            try_patient_invalid_decapsulation(publicKey, masterKey, idF, roles13467, idT, timeT);
            try_medical_invalid_decapsulation(publicKey, masterKey, role45, timeT, roles13467, idT, timeT);
            try_medical_invalid_decapsulation(publicKey, masterKey, role3, timeT, roles13467, idT, timeT);
            try_medical_invalid_decapsulation(publicKey, masterKey, role31, timeT, roles13467, idT, timeT);
            try_medical_invalid_decapsulation(publicKey, masterKey, role4, timeF, roles13467, idT, timeT);
            try_medical_invalid_decapsulation(publicKey, masterKey, role46, timeF, roles13467, idT, timeT);
            try_medical_invalid_decapsulation(publicKey, masterKey, role467, timeF, roles13467, idT, timeT);
            try_medical_invalid_delegation(publicKey, masterKey, role3, timeT, 2, roles13467, idT, timeT);
            try_medical_invalid_delegation(publicKey, masterKey, role3, timeT, 5, roles13467, idT, timeT);
            try_invalid_audit(publicKey, roles13467, idT, timeF, roles13467, idT, timeT);
            try_invalid_audit(publicKey, roles13467, idF, timeT, roles13467, idT, timeT);
            try_invalid_audit(publicKey, roles13467, idT, timeT, role467, idT, timeT);
            System.out.println(engine.getEngineName() + " test passed");
        } catch (ClassNotFoundException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        } catch (IOException e) {
            System.out.println("setup test failed.");
            e.printStackTrace();
            System.exit(1);
        }
    }

    public void testRBACLLW15Engine() {
        this.engine = RBACLLW15Engine.getInstance();
        this.runAllTests(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

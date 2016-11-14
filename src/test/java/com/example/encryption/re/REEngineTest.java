package com.example.encryption.re;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.re.REEngine;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Revocation encryption engine test.
 */
public class REEngineTest {
    private REEngine engine;

    public REEngineTest(REEngine engine) {
        this.engine = engine;
    }

    public void processTest(PairingParameters pairingParameters) {
        // Setup
        AsymmetricKeySerPair keyPair = engine.setup(pairingParameters);
        AsymmetricKeySerParameter publicKey = keyPair.getPublic();
        AsymmetricKeySerParameter masterKey = keyPair.getPrivate();

        // KeyGen
        String id = "Identity";
        String rid = "Revocated Identity";

        AsymmetricKeySerParameter skId = engine.keyGen(publicKey, masterKey, id);
        AsymmetricKeySerParameter skRid = engine.keyGen(publicKey, masterKey, rid);

        // Encryption
        String[] rids1 = new String[]{rid, "Id_1"};
        PairingKeyEncapsulationSerPair ciphertextPairRids1 = engine.encapsulation(publicKey, rids1);
        PairingCipherSerParameter ciphertextRids1 = ciphertextPairRids1.getCiphertext();
        byte[] sessionKeyRids1 = ciphertextPairRids1.getSessionKey();
        String stringSessionKeyRids1 = new String(Hex.encode(sessionKeyRids1));

        String[] rids2 = new String[]{"Id_1", "Id_2", "Id_3", "Id_4", "Id_5", "Id_6", "Id_7", "Id_8", "Id_9", rid};
        PairingKeyEncapsulationSerPair ciphertextPairRids2 = engine.encapsulation(publicKey, rids2);
        PairingCipherSerParameter ciphertextRids2 = ciphertextPairRids2.getCiphertext();
        byte[] sessionKeyRids2 = ciphertextPairRids2.getSessionKey();
        String stringSessionKeyRids2 = new String(Hex.encode(sessionKeyRids2));

        // Decrypt with correct secret keys
        System.out.println("========================================");
        System.out.println("Test RE functionality");
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

        System.out.println("======================================");
        System.out.println("Test RE parameter serialization & de-serialization.");
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
            byte[] byteArraySkID01 = TestUtils.SerCipherParameter(skId);
            CipherParameters anSkID_1 = TestUtils.deserCipherParameters(byteArraySkID01);
            assertEquals(skId, anSkID_1);

            //serialize ciphertext01
            System.out.println("Test serialize & de-serialize ciphertext.");
            byte[] byteArrayCiphertext01 = TestUtils.SerCipherParameter(ciphertextRids1);
            CipherParameters anCiphertextID_1 = TestUtils.deserCipherParameters(byteArrayCiphertext01);
            assertEquals(ciphertextRids1, anCiphertextID_1);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("RE parameter serialization tests passed.");
        System.out.println();
    }
}

package cn.edu.buaa.crypto.encryption.hibe;

import cn.edu.buaa.crypto.TestUtils;
import cn.edu.buaa.crypto.encryption.hibe.bb04.HIBEBB04Engine;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serialization.HIBEBB04SerializationFactory;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import cn.edu.buaa.crypto.serialization.CipherParameterSerializationFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2015/10/5.
 */
public class HIBEEngineTest {
    public static void main(String[] args) {
        HIBEEngine engine = new HIBEBB04Engine();
        CipherParameterSerializationFactory serializationFactory = HIBEBB04SerializationFactory.getInstance();

        // Setup
        AsymmetricCipherKeyPair keyPair = engine.setup(160, 256, 3);
        CipherParameters publicKey = keyPair.getPublic();
        PairingParameters pairingParameters = ((PairingKeyParameters)publicKey).getParameters();

        //Serialize & deserialize public key
        Document documentPublicKey = serializationFactory.documentSerialization(publicKey);
        TestUtils.OutputXMLDocument("HIBE_Public_Key.xml", documentPublicKey);
        publicKey = serializationFactory.documentDeserialization(pairingParameters, documentPublicKey);

        CipherParameters masterKey = keyPair.getPrivate();
        //Serialize & deserialize master secret key
        TestUtils.OutputXMLDocument("HIBE_Master_Secret_Key.xml", serializationFactory.documentSerialization(masterKey));
        Document documentMasterKey = TestUtils.InputXMLDocument("HIBE_Master_Secret_Key.xml");
        CipherParameters anotherMasterKey = serializationFactory.documentDeserialization(pairingParameters, documentMasterKey);
        assertEquals(masterKey, anotherMasterKey);

        // KeyGen
        String[] ids = {"Liu", "Wei", "Ran"};

        CipherParameters sk0 = engine.keyGen(publicKey, masterKey, ids[0]);
        CipherParameters sk01 = engine.keyGen(publicKey, masterKey, ids[0], ids[1]);
        CipherParameters sk012 = engine.keyGen(publicKey, masterKey, ids[0], ids[1], ids[2]);

        CipherParameters sk1 = engine.keyGen(publicKey, masterKey, ids[1]);
        CipherParameters sk10 = engine.keyGen(publicKey, masterKey, ids[1], ids[0]);
        CipherParameters sk021 = engine.keyGen(publicKey, masterKey, ids[0], ids[2], ids[1]);

        //Serialize & deserialize secret keys
        Document documentSk0 = serializationFactory.documentSerialization(sk0);
        TestUtils.OutputXMLDocument("HIBE_Secret_Key_0.xml", documentSk0);
        sk0 = serializationFactory.documentDeserialization(pairingParameters, documentSk0);
        Document documentSk01 = serializationFactory.documentSerialization(sk01);
        TestUtils.OutputXMLDocument("HIBE_Secret_Key_01.xml", documentSk01);
        sk01 = serializationFactory.documentDeserialization(pairingParameters, documentSk01);
        Document documentSk012 = serializationFactory.documentSerialization(sk012);
        TestUtils.OutputXMLDocument("HIBE_Secret_Key_012.xml", documentSk012);
        sk012 = serializationFactory.documentDeserialization(pairingParameters, documentSk012);

        // Encryption
        String[] ids0 = new String[]{ids[0]};
        PairingKeyEncapsulationPair ciphertextPair0 = engine.encapsulation(publicKey, ids[0]);
        CipherParameters ciphertext0 = ciphertextPair0.getCiphertext();
        byte[] sessionKey0 = ciphertextPair0.getSessionKey();
        String stringSessionKey0 = new String(Hex.encode(sessionKey0));

        String[] ids01 = new String[]{ids[0], ids[1]};
        PairingKeyEncapsulationPair ciphertextPair01 = engine.encapsulation(publicKey, ids[0], ids[1]);
        CipherParameters ciphertext01 = ciphertextPair01.getCiphertext();
        byte[] sessionKey01 = ciphertextPair01.getSessionKey();
        String stringSessionKey01 = new String(Hex.encode(sessionKey01));

        String[] ids012 = new String[]{ids[0], ids[1], ids[2]};
        PairingKeyEncapsulationPair ciphertextPair012 = engine.encapsulation(publicKey, ids[0], ids[1], ids[2]);
        CipherParameters ciphertext012 = ciphertextPair012.getCiphertext();
        byte[] sessionKey012 = ciphertextPair012.getSessionKey();
        String stringSessionKey012 = new String(Hex.encode(sessionKey012));

        // Decrypt with correct secret keys
        try {
            //Decrypt ciphertext 0 using secret key 0
            assertEquals(stringSessionKey0,
                    new String(Hex.encode(engine.decapsulation(publicKey, sk0, ids0, ciphertext0)))
            );
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 01 using secret key 01
            assertEquals(stringSessionKey01,
                    new String(Hex.encode(engine.decapsulation(publicKey, sk01, ids01, ciphertext0)))
            );
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 012 using secret key 012
            assertEquals(stringSessionKey012,
                    new String(Hex.encode(engine.decapsulation(publicKey, sk012, ids012, ciphertext012)))
            );
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 01 using secret key 0
            assertEquals(stringSessionKey01,
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk0,
                            ids01,
                            ciphertextPair01.getCiphertext()
                    )))
            );
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 012 using secret key 0
            assertEquals(stringSessionKey012,
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk0,
                            ids012,
                            ciphertextPair012.getCiphertext()
                    )))
            );
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Decrypt ciphertext 012 using secret key 01
            assertEquals(stringSessionKey012,
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk01,
                            ids012,
                            ciphertextPair012.getCiphertext()
                    )))
            );
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }

        //Decrypt with incorrect secret keys
        try {
            //Decrypt ciphertext 0 using secret key 1
            assertEquals(false, stringSessionKey0.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk1,
                            ids0,
                            ciphertextPair0.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext 01 using secret key 10
            assertEquals(false, stringSessionKey01.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk10,
                            ids01,
                            ciphertextPair01.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            //Decrypt ciphertext 012 using secret key 021
            assertEquals(false, stringSessionKey012.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            sk021,
                            ids012,
                            ciphertextPair012.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e){
            //Correct if getting there, nothing to do
        }

        //Delegate & Correct Decrypt
        try {
            //Delegate sk01 using sk0 and decrypt
            assertEquals(stringSessionKey01,
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            engine.delegate(publicKey, sk0, ids[1]),
                            ids01,
                            ciphertextPair01.getCiphertext()
                    )))
            );
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Delegate sk012 using sk01 and decrypt
            assertEquals(stringSessionKey012,
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            engine.delegate(publicKey, sk01, ids[2]),
                            ids012,
                            ciphertextPair012.getCiphertext()
                    )))
            );
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        try {
            //Delegate sk012 using sk0 and decrypt
            assertEquals(stringSessionKey012,
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            engine.delegate(publicKey, engine.delegate(publicKey, sk0, ids[1]), ids[2]),
                            ids012,
                            ciphertextPair012.getCiphertext()
                    )))
            );
        } catch (InvalidCipherTextException e) {
            //Bugs if getting there
            e.printStackTrace();
            System.exit(1);
        }
        //Delegate & Incorrect Decrypt
        try {
            assertEquals(false, stringSessionKey01.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            engine.delegate(publicKey, sk0, ids[0]),
                            ids01,
                            ciphertextPair01.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            assertEquals(false, stringSessionKey012.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            engine.delegate(publicKey, sk01, ids[1]),
                            ids012,
                            ciphertextPair012.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
        try {
            assertEquals(false, stringSessionKey012.equals(
                    new String(Hex.encode(engine.decapsulation(
                            publicKey,
                            engine.delegate(publicKey, sk0, ids[2]),
                            ids012,
                            ciphertextPair012.getCiphertext()
                    )))
            ));
        } catch (InvalidCipherTextException e) {
            //Correct if getting there, nothing to do
        }
    }
}

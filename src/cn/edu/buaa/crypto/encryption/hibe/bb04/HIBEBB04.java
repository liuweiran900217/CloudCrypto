package cn.edu.buaa.crypto.encryption.hibe.bb04;

import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.generators.HIBEBB04SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.*;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serialization.HIBEBB04SerializationFactory;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import cn.edu.buaa.crypto.serialization.CipherParameterSerializationFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.encoders.Hex;
import org.w3c.dom.Document;

import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Created by Weiran Liu on 15-10-1.
 */
public class HIBEBB04 {

    public HIBEBB04() {

    }

    public AsymmetricCipherKeyPair setup(int rBitLength, int qBitLength, int maxDepth) {
        HIBEBB04KeyPairGenerator keyPairGenerator = new HIBEBB04KeyPairGenerator();
        keyPairGenerator.init(new HIBEBB04KeyPairGenerationParameters(rBitLength, qBitLength, maxDepth));

        return keyPairGenerator.generateKeyPair();
    }

    public CipherParameters keyGen(CipherParameters publicKey, CipherParameters masterKey, String... ids) {
        HIBEBB04SecretKeyGenerator secretKeyGenerator = new HIBEBB04SecretKeyGenerator();
        secretKeyGenerator.init(new HIBEBB04SecretKeyGenerationParameters(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationPair encapsulation(CipherParameters publicKey, String... ids){
        HIBEBB04KeyEncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBEBB04KeyEncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBEBB04PairingKeyEncapsulationPairGenerationParameters(
                publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation(CipherParameters publicKey, CipherParameters secretKey, CipherParameters ciphertext) {
        HIBEBB04KeyDecapsulationGenerator keyDecapsulationGenerator = new HIBEBB04KeyDecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBEBB04DecapsulationParameters(
                publicKey, secretKey, ciphertext));
        try{
            return keyDecapsulationGenerator.recoverKey();
        } catch (InvalidCipherTextException e){
            return new byte[0];
        }
    }

    public static void OutputXMLDocument(String name, Document document) {
        try {
            Transformer t = TransformerFactory.newInstance().newTransformer();
            //设置换行和缩进
            t.setOutputProperty(OutputKeys.INDENT,"yes");
            t.setOutputProperty(OutputKeys.METHOD, "xml");
            t.transform(new DOMSource(document), new StreamResult(new FileOutputStream(new File(name))));
        } catch (TransformerConfigurationException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (TransformerException e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        HIBEBB04 engine = new HIBEBB04();
        CipherParameterSerializationFactory serializationFactory = HIBEBB04SerializationFactory.getInstance();

        // Setup
        AsymmetricCipherKeyPair keyPair = engine.setup(160, 256, 3);
        CipherParameters publicKey = keyPair.getPublic();
        PairingParameters pairingParameters = ((PairingKeyParameters)publicKey).getParameters();

        //Serialize & deserialize public key
        Document documentPublicKey = serializationFactory.documentSerialization(publicKey);
        HIBEBB04.OutputXMLDocument("HIBEBB04_Public_Key.xml", documentPublicKey);
        publicKey = serializationFactory.documentDeserialization(pairingParameters, documentPublicKey);

        CipherParameters masterKey = keyPair.getPrivate();
        //Serialize & deserialize master secret key
        Document documentMasterKey = serializationFactory.documentSerialization(masterKey);
        HIBEBB04.OutputXMLDocument("HIBEBB04_Master_Secret_Key.xml", documentMasterKey);
        masterKey = serializationFactory.documentDeserialization(pairingParameters, documentMasterKey);

        // KeyGen
        String[] ids = {"Liu", "Wei", "Ran"};

        CipherParameters sk0 = engine.keyGen(publicKey, masterKey, ids[0]);
        CipherParameters sk01 = engine.keyGen(publicKey, masterKey, ids[0], ids[1]);
        CipherParameters sk012 = engine.keyGen(publicKey, masterKey, ids[0], ids[1], ids[2]);

        CipherParameters sk1 = engine.keyGen(publicKey, masterKey, ids[1]);
        CipherParameters sk10 = engine.keyGen(publicKey, masterKey, ids[1], ids[0]);
        CipherParameters sk021 = engine.keyGen(publicKey, masterKey, ids[0], ids[2], ids[1]);

        // Encryption
        PairingKeyEncapsulationPair ciphertextPair0 = engine.encapsulation(keyPair.getPublic(), ids[0]);
        PairingKeyEncapsulationPair ciphertextPair01 = engine.encapsulation(keyPair.getPublic(), ids[0], ids[1]);
        PairingKeyEncapsulationPair ciphertextPair012 = engine.encapsulation(keyPair.getPublic(), ids[0], ids[1], ids[2]);

        // Decrypt with correct secret keys
        //Decrypt ciphertext 0 using secret key 0
        assertEquals(new String(Hex.encode(ciphertextPair0.getSessionKey())), new String(Hex.encode(engine.decapsulation(keyPair.getPublic(), sk0, ciphertextPair0.getCiphertext()))));
        //Decrypt ciphertext 01 using secret key 01
        assertEquals(new String(Hex.encode(ciphertextPair01.getSessionKey())), new String(Hex.encode(engine.decapsulation(keyPair.getPublic(), sk01, ciphertextPair01.getCiphertext()))));
        //Decrypt ciphertext 012 using secret key 012
        assertEquals(new String(Hex.encode(ciphertextPair012.getSessionKey())), new String(Hex.encode(engine.decapsulation(keyPair.getPublic(), sk012, ciphertextPair012.getCiphertext()))));
        //Decrypt ciphertext 01 using secret key 0
        assertEquals(new String(Hex.encode(ciphertextPair01.getSessionKey())), new String(Hex.encode(engine.decapsulation(keyPair.getPublic(), sk0, ciphertextPair01.getCiphertext()))));
        //Decrypt ciphertext 012 using secret key 0
        assertEquals(new String(Hex.encode(ciphertextPair012.getSessionKey())), new String(Hex.encode(engine.decapsulation(keyPair.getPublic(), sk0, ciphertextPair012.getCiphertext()))));
        //Decrypt ciphertext 012 using secret key 01
        assertEquals(new String(Hex.encode(ciphertextPair012.getSessionKey())), new String(Hex.encode(engine.decapsulation(keyPair.getPublic(), sk01, ciphertextPair012.getCiphertext()))));

        //Decrypt with incorrect secret keys
        //Decrypt ciphertext 0 using secret key 1
        assertEquals(false, new String(Hex.encode(ciphertextPair0.getSessionKey())).equals(new String(Hex.encode(engine.decapsulation(keyPair.getPublic(), sk1, ciphertextPair0.getCiphertext())))));
        //Decrypt ciphertext 01 using secret key 10
        assertEquals(false, new String(Hex.encode(ciphertextPair01.getSessionKey())).equals(new String(Hex.encode(engine.decapsulation(keyPair.getPublic(), sk10, ciphertextPair01.getCiphertext())))));
        //Decrypt ciphertext 012 using secret key 021
        assertEquals(false, new String(Hex.encode(ciphertextPair012.getSessionKey())).equals(new String(Hex.encode(engine.decapsulation(keyPair.getPublic(), sk021, ciphertextPair012.getCiphertext())))));
    }
}

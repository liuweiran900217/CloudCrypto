package com.example.chameleonhash;

import cn.edu.buaa.crypto.chameleonhash.*;
import cn.edu.buaa.crypto.chameleonhash.params.*;
import cn.edu.buaa.crypto.chameleonhash.serialization.ChameleonHashXMLSerializer;
import com.example.TestUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.field.z.SymmetricZrElement;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.w3c.dom.Document;

import java.io.File;
import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class CHEngineTest {
    private CHEngine engine;
    private ChameleonHashXMLSerializer chameleonHashXMLSerializer;

    public CHEngineTest(CHEngine engine, ChameleonHashXMLSerializer chameleonHashXMLSerializer) {
        this.engine = engine;
        this.chameleonHashXMLSerializer = chameleonHashXMLSerializer;
    }

    public void processTest(int rBitLength, int qBitLength) {
        //KeyGen
        ChameleonHashAsymmetricCipherKeyPair keyPair = this.engine.keyGen(rBitLength, qBitLength);
        ChameleonHashPublicKeyParameters publicKey = keyPair.getPublic();
        ChameleonHashSecretKeyParameters secretKey = keyPair.getPrivate();
        PairingParameters pairingParameters = publicKey.getParameters();

        //Hash
        String message1 = "This is message 1";
        String message2 = "This is message 2";
        ChameleonHashResultParameters hash1Parameters = this.engine.chameleonHash(publicKey, message1.getBytes());
        ChameleonHashResultParameters hash2Parameters = this.engine.chameleonHash(publicKey, message2.getBytes());
        System.out.println("========================================");
        System.out.println("Test inequality with different messages");
        System.out.println("Message 1:" + message1);
        System.out.println("Message 2:" + message2);
        assertEquals(false, hash1Parameters.getHashResult().equals(hash2Parameters.getHashResult()));

        System.out.println("========================================");
        System.out.println("Test equality without / with randomness r");
        System.out.println("Message 1:" + message1);
        Element[] r1 = hash1Parameters.getRs();
        ChameleonHashResultParameters hash1ParametersPrime = this.engine.chameleonHash(publicKey, message1.getBytes(), r1);
        assertEquals(hash1Parameters.getHashResult(), hash1ParametersPrime.getHashResult());
        System.out.println("Expect:" + hash1Parameters.getHashResult() + "\nActual:" +  hash1ParametersPrime.getHashResult());

        System.out.println("Message 2:" + message2);
        Element[] r2 = hash2Parameters.getRs();
        ChameleonHashResultParameters hash2ParametersPrime = this.engine.chameleonHash(publicKey, message2.getBytes(), r2);
        assertEquals(hash2Parameters.getHashResult(), hash2ParametersPrime.getHashResult());
        System.out.println("Expect:" + hash2Parameters.getHashResult() + "\nActual:" +  hash2ParametersPrime.getHashResult());

        System.out.println("========================================");
        System.out.println("Test collision");
        System.out.println("Message 1:" + message1);
        System.out.println("Message 2:" + message2);
        ChameleonHashResultParameters hash1CollisionParameters = this.engine.collision(secretKey, hash1Parameters, message2.getBytes());
        //Need to exact r and recompute the hash result
        Element[] rCollision = hash1CollisionParameters.getRs();
        ChameleonHashResultParameters hash1CollisionParametersPrime = this.engine.chameleonHash(publicKey, message2.getBytes(), rCollision);
        assertEquals(hash1Parameters.getHashResult(), hash1CollisionParametersPrime.getHashResult());
        BigInteger bigInteger = hash1Parameters.getHashResult().toBigInteger();
        System.out.println("Expect:" + hash1Parameters.getHashResult() + "\nActual:" +  hash1CollisionParametersPrime.getHashResult());

        //Test Serialize & deserialize
        if (this.chameleonHashXMLSerializer != null) {
            File file = new File("serializations/chameleonhash");
            file.mkdir();

            //Serialize & deserialize public key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing public key");
            TestUtils.OutputXMLDocument("serializations/chameleonhash/CH_Public_Key.xml", this.chameleonHashXMLSerializer.documentSerialization(publicKey));
            Document documentPublicKey = TestUtils.InputXMLDocument("serializations/chameleonhash/CH_Public_Key.xml");
            ChameleonHashParameters anoPublicKey = this.chameleonHashXMLSerializer.documentDeserialization(pairingParameters, documentPublicKey);
            assertEquals(publicKey, anoPublicKey);


            //Serialize & deserialize secret key
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing secret key");
            TestUtils.OutputXMLDocument("serializations/chameleonhash/CH_Secret_Key.xml", this.chameleonHashXMLSerializer.documentSerialization(secretKey));
            Document documentSecretKey = TestUtils.InputXMLDocument("serializations/chameleonhash/CH_Secret_Key.xml");
            ChameleonHashParameters anoSecretKey = this.chameleonHashXMLSerializer.documentDeserialization(pairingParameters, documentSecretKey);
            assertEquals(secretKey, anoSecretKey);

            //Serialize & deserialize hash result
            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing hash result 1");
            TestUtils.OutputXMLDocument("serializations/chameleonhash/CH_Hash_Result1.xml", this.chameleonHashXMLSerializer.documentSerialization(hash1Parameters));
            Document documentHash1Parameters = TestUtils.InputXMLDocument("serializations/chameleonhash/CH_Hash_Result1.xml");
            ChameleonHashParameters anoHash1Parameters = this.chameleonHashXMLSerializer.documentDeserialization(pairingParameters, documentHash1Parameters);
            assertEquals(hash1Parameters, anoHash1Parameters);

            System.out.println("======================================");
            System.out.println("Test Serializing & deserializing hash result 2");
            TestUtils.OutputXMLDocument("serializations/chameleonhash/CH_Hash_Result2.xml", this.chameleonHashXMLSerializer.documentSerialization(hash2Parameters));
            Document documentHash2Parameters = TestUtils.InputXMLDocument("serializations/chameleonhash/CH_Hash_Result2.xml");
            ChameleonHashParameters anoHash2Parameters = this.chameleonHashXMLSerializer.documentDeserialization(pairingParameters, documentHash2Parameters);
            assertEquals(hash2Parameters, anoHash2Parameters);
        }
    }
}

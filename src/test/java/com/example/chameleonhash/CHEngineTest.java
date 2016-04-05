package com.example.chameleonhash;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHashParameters;
import cn.edu.buaa.crypto.serialization.CipherParameterXMLSerializer;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class CHEngineTest {
    private CHEngine engine;

    public CHEngineTest(CHEngine engine) {
        this.engine = engine;
    }

    public void processTest(int rBitLength, int qBitLength) {
        //KeyGen
        AsymmetricCipherKeyPair keyPair = this.engine.keyGen(rBitLength, qBitLength);
        AsymmetricKeyParameter publicKey = keyPair.getPublic();
        AsymmetricKeyParameter secretKey = keyPair.getPrivate();

        //Hash
        String message1 = "This is message 1";
        String message2 = "This is message 2";
        ChameleonHashParameters hash1Parameters = this.engine.chameleonHash(publicKey, message1.getBytes());
        ChameleonHashParameters hash2Parameters = this.engine.chameleonHash(publicKey, message2.getBytes());
        System.out.println("========================================");
        System.out.println("Test inequality with different messages");
        System.out.println("Message 1:" + message1);
        System.out.println("Message 2:" + message2);
        assertEquals(false, hash1Parameters.getHashResult().equals(hash2Parameters.getHashResult()));

        System.out.println("========================================");
        System.out.println("Test equality without / with randomness r");
        System.out.println("Message 1:" + message1);
        Element[] r1 = hash1Parameters.getR();
        ChameleonHashParameters hash1ParametersPrime = this.engine.chameleonHash(publicKey, message1.getBytes(), r1);
        assertEquals(hash1Parameters.getHashResult(), hash1ParametersPrime.getHashResult());
        System.out.println("Expect:" + hash1Parameters.getHashResult() + "\nActual:" +  hash1ParametersPrime.getHashResult());

        System.out.println("Message 2:" + message2);
        Element[] r2 = hash2Parameters.getR();
        ChameleonHashParameters hash2ParametersPrime = this.engine.chameleonHash(publicKey, message2.getBytes(), r2);
        assertEquals(hash2Parameters.getHashResult(), hash2ParametersPrime.getHashResult());
        System.out.println("Expect:" + hash2Parameters.getHashResult() + "\nActual:" +  hash2ParametersPrime.getHashResult());

        System.out.println("========================================");
        System.out.println("Test collision");
        System.out.println("Message 1:" + message1);
        System.out.println("Message 2:" + message2);
        ChameleonHashParameters hash1CollisionParameters = this.engine.collision(secretKey, hash1Parameters, message2.getBytes());
        //Need to exact r and recompute the hash result
        Element[] rCollision = hash1CollisionParameters.getR();
        ChameleonHashParameters hash1CollisionParametersPrime = this.engine.chameleonHash(publicKey, message2.getBytes(), rCollision);
        assertEquals(hash1Parameters.getHashResult(), hash1CollisionParametersPrime.getHashResult());
        System.out.println("Expect:" + hash1Parameters.getHashResult() + "\nActual:" +  hash1CollisionParametersPrime.getHashResult());
    }
}

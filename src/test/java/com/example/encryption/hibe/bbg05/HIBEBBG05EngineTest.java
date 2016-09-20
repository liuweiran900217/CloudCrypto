package com.example.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serialization.HIBEBBG05XMLSerializer;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import com.example.encryption.hibe.HIBEEngineTest;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE engine.
 */
public class HIBEBBG05EngineTest {
    public static void main(String[] args) {
        HIBEEngine engine = HIBEBBG05Engine.getInstance();
        PairingParameterXMLSerializer schemeXMLSerializer = HIBEBBG05XMLSerializer.getInstance();

        HIBEEngineTest engineTest = new HIBEEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(160, 512, 10);
    }
}
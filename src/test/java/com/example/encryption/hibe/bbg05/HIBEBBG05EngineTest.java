package com.example.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.HIBEBBG05Engine;
import cn.edu.buaa.crypto.serialization.CipherParameterXMLSerializer;
import com.example.HIBEEngineTest;

/**
 * Created by Weiran Liu on 2015/11/3.
 */
public class HIBEBBG05EngineTest {
    public static void main(String[] args) {
        HIBEEngine engine = new HIBEBBG05Engine();
        CipherParameterXMLSerializer schemeXMLSerializer = null;

        HIBEEngineTest engineTest = new HIBEEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(160, 256, 10);
    }
}
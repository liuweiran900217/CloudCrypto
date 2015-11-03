package cn.edu.buaa.crypto.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngineTest;
import cn.edu.buaa.crypto.serialization.CipherParameterXMLSerializer;

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
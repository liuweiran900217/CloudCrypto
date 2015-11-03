package cn.edu.buaa.crypto.encryption.hibe.bbg05;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngineTest;
import cn.edu.buaa.crypto.serialization.CipherParameterSerializationFactory;

/**
 * Created by Weiran Liu on 2015/11/3.
 */
public class HIBEBBG05EngineTest {
    public static void main(String[] args) {
        HIBEEngine engine = new HIBEBBG05Engine();
        CipherParameterSerializationFactory serializationFactory = null;

        HIBEEngineTest engineTest = new HIBEEngineTest(engine, serializationFactory);
        engineTest.processTest(160, 256, 10);
    }
}
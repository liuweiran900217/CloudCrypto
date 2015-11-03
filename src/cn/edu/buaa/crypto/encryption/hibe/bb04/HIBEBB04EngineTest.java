package cn.edu.buaa.crypto.encryption.hibe.bb04;

import cn.edu.buaa.crypto.encryption.hibe.HIBEEngine;
import cn.edu.buaa.crypto.encryption.hibe.HIBEEngineTest;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serialization.HIBEBB04SerializationFactory;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.serialization.CipherParameterSerializationFactory;

/**
 * Created by Weiran Liu on 2015/11/3.
 */
public class HIBEBB04EngineTest {
    public static void main(String[] args) {
        HIBEEngine engine = new HIBEBB04Engine();
        CipherParameterSerializationFactory serializationFactory = HIBEBB04SerializationFactory.getInstance();

        HIBEEngineTest engineTest = new HIBEEngineTest(engine, serializationFactory);
        engineTest.processTest(160, 256, 10);
    }
}

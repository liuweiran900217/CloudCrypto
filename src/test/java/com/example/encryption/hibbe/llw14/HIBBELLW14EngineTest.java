package com.example.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serialization.HIBBELLW14XMLSerializer;
import cn.edu.buaa.crypto.algebra.PairingParameterXMLSerializer;
import com.example.encryption.hibbe.HIBBEEngineTest;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * 2014 Liu-Liu-Wu HIBBE engine test.
 */
public class HIBBELLW14EngineTest {
    public static void main(String[] args) {
        HIBBEEngine engine = HIBBELLW14Engine.getInstance();
        PairingParameterXMLSerializer schemeXMLSerializer = HIBBELLW14XMLSerializer.getInstance();

        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(-1, 256);
    }
}

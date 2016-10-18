package com.example.encryption.hibbe.llw16;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.HIBBELLW16Engine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serialization.HIBBELLW16aXMLSerializer;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import com.example.encryption.hibbe.HIBBEEngineTest;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Test Liu-Liu-Wu 2016 HIBBE engine.
 */
public class HIBBELLW16EngineTest {
    public static void main(String[] args) {
        HIBBEEngine engine = HIBBELLW16Engine.getInstance();
        PairingParameterXMLSerializer schemeXMLSerializer = HIBBELLW16aXMLSerializer.getInstance();

        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(160, 256);
    }
}

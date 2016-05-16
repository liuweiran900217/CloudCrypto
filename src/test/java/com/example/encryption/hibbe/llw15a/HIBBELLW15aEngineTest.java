package com.example.encryption.hibbe.llw15a;

import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw15a.HIBBELLW15aEngine;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import com.example.encryption.hibbe.HIBBEEngineTest;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW15aEngineTest {
    public static void main(String[] args) {
        HIBBEEngine engine = new HIBBELLW15aEngine();
        PairingParameterXMLSerializer schemeXMLSerializer = null;

        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(160, 128);
    }
}

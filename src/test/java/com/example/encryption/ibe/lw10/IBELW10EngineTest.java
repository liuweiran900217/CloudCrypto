package com.example.encryption.ibe.lw10;

import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.lw10.IBELW10Engine;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serialization.IBELW10XMLSerializer;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import com.example.encryption.ibe.IBEEngineTest;

/**
 * Created by Weiran Liu on 16/5/7.
 *
 * Lewko-Sahai-Waters Online/Offline Revocation Encryption engine test.
 */
public class IBELW10EngineTest {
    public static void main(String[] args) {
        IBEEngine engine = IBELW10Engine.getInstance();
        PairingParameterXMLSerializer schemeXMLSerializer = IBELW10XMLSerializer.getInstance();

        IBEEngineTest engineTest = new IBEEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(-1, 256);
    }
}

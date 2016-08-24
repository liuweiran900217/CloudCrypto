package com.example.encryption.ibbe.del07;

import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import cn.edu.buaa.crypto.encryption.ibbe.del07.IBBEDel07Engine;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serialization.IBBEDel07XMLSerializer;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import com.example.encryption.ibbe.IBBEEngineTest;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * 2007 Delerablée IBBE engine test procedures
 */
public class IBBEDel07EngineTest {
    public static void main(String[] args) {
        IBBEEngine engine = new IBBEDel07Engine();
        PairingParameterXMLSerializer schemeXMLSerializer = IBBEDel07XMLSerializer.getInstance();

        IBBEEngineTest engineTest = new IBBEEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(160, 256);
    }
}

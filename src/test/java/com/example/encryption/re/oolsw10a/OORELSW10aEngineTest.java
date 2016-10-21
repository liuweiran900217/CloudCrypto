package com.example.encryption.re.oolsw10a;

import cn.edu.buaa.crypto.encryption.re.OOREEngine;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.OORELSW10aEngine;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.serialization.OORELSW10aXMLSerializer;
import cn.edu.buaa.crypto.algebra.PairingParameterXMLSerializer;
import com.example.encryption.re.OOREEngineTest;

/**
 * Created by Weiran Liu on 2016/4/10.
 *
 * Online/offline version of Lewko-Sahai-Waters Revocation scheme test.
 * The transformation follows by Liu-Liu-Wu.
 */
public class OORELSW10aEngineTest {
    public static void main(String[] args) {
        OOREEngine engine = OORELSW10aEngine.getInstance();
        PairingParameterXMLSerializer schemeXMLSerializer = OORELSW10aXMLSerializer.getInstance();

        OOREEngineTest engineTest = new OOREEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(160, 256);
    }
}

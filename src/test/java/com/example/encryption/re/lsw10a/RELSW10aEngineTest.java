package com.example.encryption.re.lsw10a;

import cn.edu.buaa.crypto.encryption.re.REEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.RELSW10aEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serialization.RELSW10aXMLSerializer;
import cn.edu.buaa.crypto.algebra.PairingParameterXMLSerializer;
import com.example.encryption.re.REEngineTest;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters Revocation scheme test.
 */
public class RELSW10aEngineTest {
    public static void main(String[] args) {
        REEngine engine = RELSW10aEngine.getInstance();
        PairingParameterXMLSerializer schemeXMLSerializer = RELSW10aXMLSerializer.getInstance();

        REEngineTest engineTest = new REEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(160, 256);
    }
}

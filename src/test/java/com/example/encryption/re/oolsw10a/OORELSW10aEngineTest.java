package com.example.encryption.re.oolsw10a;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.CHCZK04Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.CHKR00Engine;
import cn.edu.buaa.crypto.encryption.re.OOREEngine;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.OORELSW10aEngine;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.serialization.OORELSW10aXMLSerializer;
import cn.edu.buaa.crypto.pairingkem.serialization.PairingParameterXMLSerializer;
import com.example.encryption.re.OOREEngineTest;

/**
 * Created by Weiran Liu on 2016/4/10.
 */
public class OORELSW10aEngineTest {
    public static void main(String[] args) {
        CHEngine chEngine = new CHKR00Engine();
        OOREEngine engine = new OORELSW10aEngine(chEngine);
        PairingParameterXMLSerializer schemeXMLSerializer = OORELSW10aXMLSerializer.getInstance();

        OOREEngineTest engineTest = new OOREEngineTest(engine, schemeXMLSerializer);
        engineTest.processTest(160, 512);
    }
}

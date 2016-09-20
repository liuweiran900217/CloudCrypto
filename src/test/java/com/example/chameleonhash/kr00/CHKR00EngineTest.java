package com.example.chameleonhash.kr00;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.CHKR00Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.serialization.CHKR00XMLSerializer;
import cn.edu.buaa.crypto.chameleonhash.serialization.ChameleonHashXMLSerializer;
import com.example.chameleonhash.CHEngineTest;

/**
 * Created by Weiran Liu on 2016/4/5.
 *
 * Katz-Rabin Chameleon hash engine.
 */
public class CHKR00EngineTest {
    public static void main(String[] args) {
        CHEngine engine = CHKR00Engine.getInstance();
        ChameleonHashXMLSerializer chameleonHashXMLSerializer = CHKR00XMLSerializer.getInstance();
        CHEngineTest engineTest = new CHEngineTest(engine, chameleonHashXMLSerializer);
        engineTest.processTest(160, 512);
    }
}

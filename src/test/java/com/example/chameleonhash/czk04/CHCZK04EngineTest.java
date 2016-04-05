package com.example.chameleonhash.czk04;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.czk04.CHCZK04Engine;
import cn.edu.buaa.crypto.serialization.CipherParameterXMLSerializer;
import com.example.chameleonhash.CHEngineTest;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class CHCZK04EngineTest {
    public static void main(String[] args) {
        CHEngine engine = new CHCZK04Engine();

        CHEngineTest engineTest = new CHEngineTest(engine);
        engineTest.processTest(160, 256);
    }
}

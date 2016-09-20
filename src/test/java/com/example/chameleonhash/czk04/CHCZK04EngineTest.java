package com.example.chameleonhash.czk04;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.CHCZK04Engine;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.serialization.CHCZK04XMLSerializer;
import cn.edu.buaa.crypto.chameleonhash.serialization.ChameleonHashXMLSerializer;
import com.example.chameleonhash.CHEngineTest;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Chen-Zhang-Kim Chameleon hash engine test.
 */
public class CHCZK04EngineTest {
    public static void main(String[] args) {
        CHEngine engine = CHCZK04Engine.getInstance();
        ChameleonHashXMLSerializer chameleonHashXMLSerializer = CHCZK04XMLSerializer.getInstance();

        CHEngineTest engineTest = new CHEngineTest(engine, chameleonHashXMLSerializer);
        engineTest.processTest(160, 512);
    }
}

package com.example.chameleonhash.kr00;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.CHKR00Engine;
import com.example.chameleonhash.CHEngineTest;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class CHKR00EngineTest {
    public static void main(String[] args) {
        CHEngine engine = new CHKR00Engine();
        CHEngineTest engineTest = new CHEngineTest(engine);
        engineTest.processTest(160, 512);
    }
}

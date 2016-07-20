package com.example.access.lsss.lsw10;

import cn.edu.buaa.crypto.access.lsss.lsw10.LSSSLW10Engine;
import com.example.access.AccessControlEngineTest;

/**
 * Created by Weiran Liu on 2016/7/20.
 */
public class LSSSLW10EngineTest {
    public static void main(String[] args) {
        AccessControlEngineTest accessTreeEngineTest = new AccessControlEngineTest(LSSSLW10Engine.getInstance());
        accessTreeEngineTest.testAccessPolicy();
    }
}

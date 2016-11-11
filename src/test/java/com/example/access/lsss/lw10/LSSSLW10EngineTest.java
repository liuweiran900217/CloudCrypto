package com.example.access.lsss.lw10;

import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import com.example.access.AccessControlEngineTest;

/**
 * Created by Weiran Liu on 2016/7/20.
 *
 * Lewko-Waters LSSS engine test.
 */
public class LSSSLW10EngineTest {
    public static void main(String[] args) {
        AccessControlEngineTest accessTreeEngineTest = new AccessControlEngineTest(LSSSLW10Engine.getInstance());
        accessTreeEngineTest.testAccessPolicy();
    }
}

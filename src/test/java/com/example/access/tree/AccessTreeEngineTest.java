package com.example.access.tree;

import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import com.example.access.AccessControlEngineTest;

/**
 * Created by Weiran Liu on 2016/7/20.
 *
 * Access tree engine test.
 */
public class AccessTreeEngineTest {
    public static void main(String[] args) {
        AccessControlEngineTest accessTreeEngineTest = new AccessControlEngineTest(AccessTreeEngine.getInstance());
        accessTreeEngineTest.testAccessPolicy();
    }
}

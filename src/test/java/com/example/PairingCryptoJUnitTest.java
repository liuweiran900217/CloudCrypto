package com.example;

import com.example.access.lsss.lw10.LSSSLW10EngineJUnitTest;
import com.example.access.parser.PolicyParserJUnitTest;
import com.example.access.tree.AccessTreeEngineJUnitTest;
import com.example.application.llw15.RBACLLW15EngineJUnitTest;
import com.example.chameleonhash.ChameleonHasherJunitTest;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * All Unit Test
 */
public class PairingCryptoJUnitTest {
    public static void main(String[] args) {
        System.out.println("****************************************");
        System.out.println("Test ChameleonHashers");
        junit.textui.TestRunner.run(ChameleonHasherJunitTest.class);
        System.out.println();

//        System.out.println("****************************************");
//        System.out.println("Test PolicyParser");
//        junit.textui.TestRunner.run(PolicyParserJUnitTest.class);
//        System.out.println();

//        System.out.println("****************************************");
//        System.out.println("Test AccessTreeEngine");
//        junit.textui.TestRunner.run(AccessTreeEngineJUnitTest.class);
//        System.out.println();

//        System.out.println("****************************************");
//        System.out.println("Test LSSSLW10Engine");
//        junit.textui.TestRunner.run(LSSSLW10EngineJUnitTest.class);
//        System.out.println();

//        System.out.println("****************************************");
//        System.out.println("Test RBACLL15Engine");
//        junit.textui.TestRunner.run(RBACLLW15EngineJUnitTest.class);
//        System.out.println();
    }
}

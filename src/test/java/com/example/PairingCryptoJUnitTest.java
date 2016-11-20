package com.example;

import com.example.encryption.abe.kpabe.gpsw06a.KPABEGPSW06aEngineJunitTest;
import com.example.encryption.hibbe.llw14.HIBBELLW14EngineJUnitTest;
import com.example.encryption.hibbe.llw16a.HIBBELLW16aEngineJUnitTest;
import com.example.encryption.hibbe.llw16b.HIBBELLW16bEngineJUnitTest;
import com.example.encryption.hibbe.llw17.HIBBELLW17EngineJUnitTest;
import com.example.encryption.hibe.bb04.HIBEBB04EngineJUnitTest;
import com.example.encryption.hibe.bbg05.HIBEBBG05EngineJUnitTest;
import com.example.encryption.ibbe.del07.IBBEDel07EngineJUnitTest;
import com.example.encryption.ibe.lw10.IBELW10EngineJUnitTest;
import com.example.encryption.re.lsw10a.RELSW10aEngineJUnitTest;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * All Unit Test
 */
public class PairingCryptoJUnitTest {
    public static void main(String[] args) {
//        System.out.println("****************************************");
//        System.out.println("Test ChameleonHashers");
//        junit.textui.TestRunner.run(ChameleonHasherJunitTest.class);
//        System.out.println();

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

        System.out.println("****************************************");
        System.out.println("Test KPABEEngine");
        junit.textui.TestRunner.run(KPABEGPSW06aEngineJunitTest.class);
        System.out.println();

        System.out.println("****************************************");
        System.out.println("Test HIBBEEngine");
        junit.textui.TestRunner.run(HIBBELLW14EngineJUnitTest.class);
        junit.textui.TestRunner.run(HIBBELLW16aEngineJUnitTest.class);
        junit.textui.TestRunner.run(HIBBELLW16bEngineJUnitTest.class);
        junit.textui.TestRunner.run(HIBBELLW17EngineJUnitTest.class);
        System.out.println();

        System.out.println("****************************************");
        System.out.println("Test HIBEEngine");
        junit.textui.TestRunner.run(HIBEBB04EngineJUnitTest.class);
        junit.textui.TestRunner.run(HIBEBBG05EngineJUnitTest.class);
        System.out.println();

        System.out.println("****************************************");
        System.out.println("Test IBBEEngine");
        junit.textui.TestRunner.run(IBBEDel07EngineJUnitTest.class);
        System.out.println();

        System.out.println("****************************************");
        System.out.println("Test IBEEngine");
        junit.textui.TestRunner.run(IBELW10EngineJUnitTest.class);
        System.out.println();

        System.out.println("****************************************");
        System.out.println("Test REngine");
        junit.textui.TestRunner.run(RELSW10aEngineJUnitTest.class);
        System.out.println();
    }
}

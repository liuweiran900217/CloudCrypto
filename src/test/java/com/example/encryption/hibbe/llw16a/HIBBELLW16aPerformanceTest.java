package com.example.encryption.hibbe.llw16a;

import cn.edu.buaa.crypto.encryption.hibbe.llw16a.HIBBELLW16aEngine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEPerformanceTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Liu-Liu-Wu prime-order HIBBE performance test.
 */
public class HIBBELLW16aPerformanceTest {
    public static void main(String[] args) {
        new HIBBEPerformanceTest(PairingUtils.PATH_a_160_512,
                TestUtils.DEFAULT_PRIME_ORDER_TEST_ROUND,
                HIBBELLW16aEngine.getInstance(), HIBBELLW16aEngine.SCHEME_NAME + ".txt").performanceTest();
    }
}

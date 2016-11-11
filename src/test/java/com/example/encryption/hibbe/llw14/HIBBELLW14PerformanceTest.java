package com.example.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEPerformanceTest;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Liu-Liu-Wu composite-order HIBBE performance test.
 */
public class HIBBELLW14PerformanceTest {
    public static void main(String[] args) {
        new HIBBEPerformanceTest(
                PairingUtils.PATH_a1_3_512,
                TestUtils.DEFAULT_COMPOSITE_ORDER_TEST_ROUND,
                HIBBELLW14Engine.getInstance(), HIBBELLW14Engine.SCHEME_NAME + ".txt").performanceTest();
    }
}

package com.example.encryption.hibbe.llw17;

import cn.edu.buaa.crypto.encryption.hibbe.llw17.HIBBELLW17Engine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEPerformanceTest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE performance test.
 */
public class HIBBELLW17PerformanceTest {
    public static void main(String[] args) {
        new HIBBEPerformanceTest(
                TestUtils.TEST_PAIRING_PARAMETERS_PATH_a1_3_128,
                TestUtils.DEFAULT_SIMU_TEST_ROUND,
                HIBBELLW17Engine.getInstance(), HIBBELLW17Engine.SCHEME_NAME + ".txt").performanceTest();
    }
}

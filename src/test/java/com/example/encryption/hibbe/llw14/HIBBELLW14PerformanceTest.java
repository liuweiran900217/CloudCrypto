package com.example.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEPerformanceTest;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Liu-Liu-Wu composite-order HIBBE performance test.
 */
public class HIBBELLW14PerformanceTest {
    public static void main(String[] args) {
        new HIBBEPerformanceTest(TestUtils.R_BIT_LENGTH, TestUtils.Q_BIT_LENGTH,
                HIBBELLW14Engine.getInstance(), "HIBBE-LLW14.txt").performanceTest();
    }
}

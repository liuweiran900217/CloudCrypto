package com.example.encryption.hibbe.llw16a;

import cn.edu.buaa.crypto.encryption.hibbe.llw16a.HIBBELLW16aEngine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEPerformanceTest;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Liu-Liu-Wu prime-order HIBBE performance test.
 */
public class HIBBELLW16aPerformanceTest {
    public static void main(String[] args) {
        //the q bit length is chosen according to the reviewer #2 from The Computer Journal.

        new HIBBEPerformanceTest(TestUtils.R_BIT_LENGTH, TestUtils.Q_BIT_LENGTH,
                HIBBELLW16aEngine.getInstance(), "HIBBE-LLW16a.txt").performanceTest();
    }
}

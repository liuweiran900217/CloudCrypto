package com.example.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import com.example.encryption.hibbe.HIBBEPerformanceTest;

/**
 * Created by Weiran Liu on 16/11/8.
 *
 * Liu-Liu-Wu composite-order HIBBE scheme performance test.
 */
public class HIBBELLW14PerformanceTest {
    public static void main(String[] args) {
        //the q bit length is chosen according to the reviewer #2 from The Computer Journal.
        final int q_bit_length = 512;

        HIBBEPerformanceTest performanceTest = new HIBBEPerformanceTest(HIBBELLW14Engine.getInstance(), "HIBBE-LLW14.txt");
        performanceTest.setQBitLength(q_bit_length);
        performanceTest.setTestRound(25);
        performanceTest.performanceTest();
    }
}

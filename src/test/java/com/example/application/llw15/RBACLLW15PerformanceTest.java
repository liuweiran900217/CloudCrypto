package com.example.application.llw15;

import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;

/**
 * Created by Weiran Liu on 2016/10/8.
 *
 * Liu-Liu-Wu EHR role-based access control scheme performance test
 */
public class RBACLLW15PerformanceTest {
    private static final int r_bit_length = 160;
    //the q bit length is chosen according to the reviewer #2 from The Computer Journal.
    private static final int q_bit_length = 512;
    //the test round is chosen according to the full version of our paper.
    private static final int test_round = 100;

    private RBACLLW15Engine engine;;

    public RBACLLW15PerformanceTest(RBACLLW15Engine engine) {
        this.engine = engine;
    }
}

package com.example.encryption.ibbe.del07;

import cn.edu.buaa.crypto.encryption.ibbe.IBBEEngine;
import cn.edu.buaa.crypto.encryption.ibbe.del07.IBBEDel07Engine;
import com.example.TestUtils;
import com.example.encryption.ibbe.IBBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Delerablée IBBE engine test.
 */
public class IBBEDel07EngineTest {
    public static void main(String[] args) {
        IBBEEngine engine = IBBEDel07Engine.getInstance();
        IBBEEngineTest engineTest = new IBBEEngineTest(engine);

        engineTest.processTest(PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256));
    }
}

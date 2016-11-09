package com.example.encryption.hibbe.llw16a;

import cn.edu.buaa.crypto.algebra.generators.PairingParametersGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.HIBBELLW16aEngine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Test Liu-Liu-Wu prime-order HIBBE scheme.
 */
public class HIBBELLW16aEngineTest {
    public static void main(String[] args) {
        HIBBEEngine engine = HIBBELLW16aEngine.getInstance();

        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine);

        PairingParametersGenerationParameters pairingParametersGenerationParameters =
                new PairingParametersGenerationParameters(PairingParametersGenerationParameters.PairingType.TYPE_A,
                        TestUtils.R_BIT_LENGTH, TestUtils.Q_BIT_LENGTH);
        PairingParametersGenerator pairingParametersGenerator = new PairingParametersGenerator();
        pairingParametersGenerator.init(pairingParametersGenerationParameters);
        PairingParameters pairingParameters = pairingParametersGenerator.generateParameters();
        engineTest.processTest(pairingParameters);
    }
}

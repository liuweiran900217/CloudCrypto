package com.example.encryption.hibbe.llw14;

import cn.edu.buaa.crypto.algebra.generators.PairingParametersGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import com.example.TestUtils;
import com.example.encryption.hibbe.HIBBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * 2014 Liu-Liu-Wu HIBBE engine test.
 */
public class HIBBELLW14EngineTest {
    public static void main(String[] args) {
        HIBBEEngine engine = HIBBELLW14Engine.getInstance();
        HIBBEEngineTest engineTest = new HIBBEEngineTest(engine);

        PairingParametersGenerationParameters pairingParametersGenerationParameters =
                new PairingParametersGenerationParameters(TestUtils.NUM_OF_PRIME_FACTORS, TestUtils.PRIME_BIT_LENGTH);
        PairingParametersGenerator pairingParametersGenerator = new PairingParametersGenerator();
        pairingParametersGenerator.init(pairingParametersGenerationParameters);
        PairingParameters pairingParameters = pairingParametersGenerator.generateParameters();
        engineTest.processTest(pairingParameters);
    }
}

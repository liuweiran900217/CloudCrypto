package com.example.encryption.ibe.lw10;

import cn.edu.buaa.crypto.algebra.generators.PairingParametersGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameters;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.lw10.IBELW10Engine;
import com.example.encryption.ibe.IBEEngineTest;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/5/7.
 *
 * Lewko-Sahai-Waters Online/Offline Revocation Encryption engine test.
 */
public class IBELW10EngineTest {
    public static void main(String[] args) {
        IBEEngine engine = IBELW10Engine.getInstance();
        IBEEngineTest engineTest = new IBEEngineTest(engine);

        PairingParametersGenerationParameters pairingParametersGenerationParameters =
                new PairingParametersGenerationParameters(3, 256);
        PairingParametersGenerator pairingParametersGenerator = new PairingParametersGenerator();
        pairingParametersGenerator.init(pairingParametersGenerationParameters);
        PairingParameters pairingParameters = pairingParametersGenerator.generateParameters();
        engineTest.processTest(pairingParameters);
    }
}

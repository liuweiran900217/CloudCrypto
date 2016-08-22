package com.example.algebra;

import cn.edu.buaa.crypto.algebra.HornerRule;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

/**
 * Created by Weiran Liu on 2016/8/22.
 *
 * Test class for HornerRule
 */
public class HornerRuleTest {
    public static void main(String[] args) {
        PropertiesParameters parameters;
        Pairing pairing;
        Element g;
        // Generate curve parameters
        while (true) {
            PairingParametersGenerator parametersGenerator = new TypeACurveGenerator(160, 256);
            parameters = (PropertiesParameters) parametersGenerator.generate();
            pairing = PairingFactory.getPairing(parameters);

            g = pairing.getG1().newRandomElement().getImmutable();
            if (!pairing.pairing(g, g).isOne()) { break; }
        }

        Element[] elementaryCoefficients = new Element[9];
        for (int i = 1; i < 10; i++) {
            elementaryCoefficients[i-1] = pairing.getZr().newElement(i);
        }
        Element[] allCofficients = HornerRule.ComputeEfficients(pairing, elementaryCoefficients);
        for (Element coefficient : allCofficients) {
            System.out.println(coefficient);
        }
    }
}

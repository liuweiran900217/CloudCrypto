package com.example.algebra;

import cn.edu.buaa.crypto.algebra.algorithms.HornerRule;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

/**
 * Created by Weiran Liu on 2016/8/22.
 *
 * Test class for HornerRule
 */
public class HornerRuleTest {
    public static void main(String[] args) {
        PropertiesParameters parameters = PairingUtils.GenerateTypeAParameters(160, 256);
        Pairing pairing = PairingFactory.getPairing(parameters);

        Element[] elementaryCoefficients = new Element[9];
        for (int i = 1; i < 10; i++) {
            elementaryCoefficients[i-1] = pairing.getZr().newElement(i);
        }
        Element[] allCoefficients = HornerRule.ComputeEfficients(pairing, elementaryCoefficients);
        for (Element coefficient : allCoefficients) {
            System.out.println(coefficient);
        }
    }
}

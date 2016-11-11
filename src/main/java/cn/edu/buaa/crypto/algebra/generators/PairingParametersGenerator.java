package cn.edu.buaa.crypto.algebra.generators;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.e.TypeECurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 2016/10/21.
 *
 * Pairing parameter generator.
 */
public class PairingParametersGenerator {
    private PairingParametersGenerationParameter pairingParametersGenerationParameter;

    public void init(PairingParametersGenerationParameter pairingParametersGenerationParameter) {
        this.pairingParametersGenerationParameter = pairingParametersGenerationParameter;
    }

    public PairingParameters generateParameters() {
        switch (pairingParametersGenerationParameter.getPairingType()) {
            case TYPE_A:
                int rBitLengthTypeA = pairingParametersGenerationParameter.getRBitLength();
                int qBitLengthTypeA = pairingParametersGenerationParameter.getQBitLength();
                return generate_type_a_curve_params(rBitLengthTypeA, qBitLengthTypeA);
            case TYPE_A1:
                int nTypeA1 = pairingParametersGenerationParameter.getN();
                int qBitLengthTypeA1 = pairingParametersGenerationParameter.getQBitLength();
                return generate_type_a1_curve_params(nTypeA1, qBitLengthTypeA1);
            case TYPE_E:
                int rBitLengthTypeE = pairingParametersGenerationParameter.getRBitLength();
                int qBitLengthTypeE = pairingParametersGenerationParameter.getQBitLength();
                return generate_type_e_curve_params(rBitLengthTypeE, qBitLengthTypeE);
            case TYPE_F:
                throw new IllegalArgumentException("Curve type not support.");
            default:
                throw new IllegalArgumentException("Unknown curve type.");
        }
    }

    private static PropertiesParameters generate_type_a_curve_params(int rBitLength, int qBitLength) {
        PropertiesParameters parameters;
        Pairing pairing;
        Element g;
        // Generate curve parameters
        while (true) {
            it.unisa.dia.gas.jpbc.PairingParametersGenerator parametersGenerator = new TypeACurveGenerator(rBitLength, qBitLength);
            parameters = (PropertiesParameters) parametersGenerator.generate();
            pairing = PairingFactory.getPairing(parameters);
            g = pairing.getG1().newRandomElement().getImmutable();
            if (!pairing.pairing(g, g).isOne()) { break; }
        }
        return parameters;
    }

    private static PropertiesParameters generate_type_a1_curve_params(int n, int qBitLength) {
        PropertiesParameters parameters;
        Pairing pairing;
        Element generator;
        Element g;

        // Generate curve parameters
        while (true) {
            it.unisa.dia.gas.jpbc.PairingParametersGenerator parametersGenerator = new TypeA1CurveGenerator(n, qBitLength);
            parameters = (PropertiesParameters) parametersGenerator.generate();
            pairing = PairingFactory.getPairing(parameters);
            generator = pairing.getG1().newRandomElement().getImmutable();
            g = ElementUtils.getGenerator(pairing, generator, parameters, 0, n).getImmutable();
            if (!pairing.pairing(g, g).isOne()) { break; }
        }
        return parameters;
    }

    private static PropertiesParameters generate_type_e_curve_params(int rBitLength, int qBitLength) {
        PropertiesParameters parameters;
        Pairing pairing;
        Element g;

        // Generate curve parameters
        while (true) {
            it.unisa.dia.gas.jpbc.PairingParametersGenerator parametersGenerator = new TypeECurveGenerator(rBitLength, qBitLength);
            parameters = (PropertiesParameters) parametersGenerator.generate();
            pairing = PairingFactory.getPairing(parameters);
            g = pairing.getG1().newRandomElement().getImmutable();
            if (!pairing.pairing(g, g).isOne()) { break; }
        }
        return parameters;
    }
}

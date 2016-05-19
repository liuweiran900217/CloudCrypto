package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15KeyPairGenerationParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15MasterSecretKeyParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/19.
 */
public class RBACLLW15KeyPairGenerator {
    private RBACLLW15KeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (RBACLLW15KeyPairGenerationParameters)keyGenerationParameters;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PropertiesParameters parameters;
        Pairing pairing;
        Element generator;
        Element g;

        // Generate curve parameters
        while (true) {
            parameters = generateCurveParams();
            pairing = PairingFactory.getPairing(parameters);

            g = pairing.getG1().newRandomElement().getImmutable();
            if (!pairing.pairing(g, g).isOne()) { break; }
        }

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element g1 = g.powZn(alpha).getImmutable();
        Element g2 = pairing.getG1().newRandomElement().getImmutable();
        Element g3 = pairing.getG1().newRandomElement().getImmutable();
        Element gh = pairing.getG1().newRandomElement().getImmutable();
        Element g2Alpha = g2.powZn(alpha).getImmutable();
        Element u0 = pairing.getG1().newRandomElement().getImmutable();
        Element uv = pairing.getG1().newRandomElement().getImmutable();
        Element[] u = new Element[this.parameters.getMaxRoleNumber()];
        for (int i=0; i<u.length; i++) {
            u[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        return new AsymmetricCipherKeyPair(
                new RBACLLW15PublicKeyParameters(parameters, g, g1, g2, g3, gh, u0, uv, u),
                new RBACLLW15MasterSecretKeyParameters(parameters, g2Alpha));
    }

    private PropertiesParameters generateCurveParams() {
        PairingParametersGenerator parametersGenerator = new TypeACurveGenerator(parameters.getRBitLength(), parameters.getQBitLength());
        return (PropertiesParameters) parametersGenerator.generate();
    }
}

package cn.edu.buaa.crypto.encryption.hibbe.llw16.generators;

import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16KeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16KeyPairGenerator {
    private HIBBELLW16KeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBBELLW16KeyPairGenerationParameters)keyGenerationParameters;
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
        Element g2Alpha = g2.powZn(alpha).getImmutable();
        Element[] u = new Element[this.parameters.getMaxUser()];
        for (int i=0; i<u.length; i++) {
            u[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        return new AsymmetricCipherKeyPair(
                new HIBBELLW16PublicKeyParameters(parameters, g, g1, g2, g3, u),
                new HIBBELLW16MasterSecretKeyParameters(parameters, g2Alpha));
    }

    private PropertiesParameters generateCurveParams() {
        PairingParametersGenerator parametersGenerator = new TypeACurveGenerator(parameters.getRBitLength(), parameters.getQBitLength());
        return (PropertiesParameters) parametersGenerator.generate();
    }
}

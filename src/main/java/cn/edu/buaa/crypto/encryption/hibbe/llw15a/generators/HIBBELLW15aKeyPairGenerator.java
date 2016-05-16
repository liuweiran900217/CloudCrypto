package cn.edu.buaa.crypto.encryption.hibbe.llw15a.generators;

import cn.edu.buaa.crypto.encryption.hibbe.llw15a.params.HIBBELLW15aKeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw15a.params.HIBBELLW15aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw15a.params.HIBBELLW15aPublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW15aKeyPairGenerator {
    private HIBBELLW15aKeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBBELLW15aKeyPairGenerationParameters)keyGenerationParameters;
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
            generator = pairing.getG1().newRandomElement().getImmutable();
            g = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
            if (!pairing.pairing(g, g).isOne()) { break; }
        }

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element gAlpha = g.powZn(alpha).getImmutable();
        Element h = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        Element X3 = ElementUtils.getGenerator(pairing, generator, parameters, 2, 3).getImmutable();
        Element[] u = new Element[this.parameters.getMaxUser()];
        for (int i=0; i<u.length; i++) {
            u[i] = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        }
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        // Remove factorization from curveParams
        parameters.remove("n0");
        parameters.remove("n1");
        parameters.remove("n2");
        return new AsymmetricCipherKeyPair(
                new HIBBELLW15aPublicKeyParameters(parameters, g, h, u, X3, eggAlpha),
                new HIBBELLW15aMasterSecretKeyParameters(parameters, gAlpha));
    }

    private PropertiesParameters generateCurveParams() {
        PairingParametersGenerator parametersGenerator = new TypeA1CurveGenerator(3, parameters.getQBitLength());
        return (PropertiesParameters) parametersGenerator.generate();
    }
}

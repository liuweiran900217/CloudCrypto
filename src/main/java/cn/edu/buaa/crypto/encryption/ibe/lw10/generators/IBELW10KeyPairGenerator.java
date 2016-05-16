package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10KeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/7.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private IBELW10KeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (IBELW10KeyPairGenerationParameters)keyGenerationParameters;
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
        Element u = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        Element h = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        Element g3Generator = ElementUtils.getGenerator(pairing, generator, parameters, 2, 3).getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        // Remove factorization from curveParams
        parameters.remove("n0");
        parameters.remove("n1");
        parameters.remove("n2");
        return new AsymmetricCipherKeyPair(
                new IBELW10PublicKeyParameters(parameters, u, g, h, eggAlpha),
                new IBELW10MasterSecretKeyParameters(parameters, alpha, g3Generator));
    }

    private PropertiesParameters generateCurveParams() {
        PairingParametersGenerator parametersGenerator = new TypeA1CurveGenerator(3, parameters.getQBitLength());
        return (PropertiesParameters) parametersGenerator.generate();
    }
}

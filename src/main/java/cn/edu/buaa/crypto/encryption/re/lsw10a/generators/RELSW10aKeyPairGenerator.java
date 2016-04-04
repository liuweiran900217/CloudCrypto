package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aKeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aPublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class RELSW10aKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private RELSW10aKeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters param) {
        this.parameters = (RELSW10aKeyPairGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PropertiesParameters parameters;
        Pairing pairing;
        Element g;

        // Generate curve parameters
        while (true) {
            parameters = generateCurveParams();
            pairing = PairingFactory.getPairing(parameters);

            g = pairing.getG1().newRandomElement().getImmutable();
            if (!pairing.pairing(g, g).isOne()) { break; }
        }

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();
        Element b2 = b.mulZn(b).getImmutable();

        Element gb = g.powZn(b).getImmutable();
        Element gb2 = g.powZn(b2).getImmutable();
        Element h = pairing.getG1().newRandomElement().getImmutable();
        Element hb = h.powZn(b).getImmutable();

        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        return new AsymmetricCipherKeyPair(
                new RELSW10aPublicKeyParameters(parameters, g, gb, gb2, hb, eggAlpha),
                new RELSW10aMasterSecretKeyParameters(parameters, alpha, b, h));
    }

    private PropertiesParameters generateCurveParams() {
        PairingParametersGenerator parametersGenerator = new TypeACurveGenerator(parameters.getRBitLength(), parameters.getQBitLength());
        return (PropertiesParameters) parametersGenerator.generate();
    }
}

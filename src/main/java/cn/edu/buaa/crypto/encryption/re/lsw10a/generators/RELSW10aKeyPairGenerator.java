package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aKeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aPublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
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
        PropertiesParameters parameters = PairingUtils.GenerateTypeAParameters(this.parameters.getRBitLength(), this.parameters.getQBitLength());
        Pairing pairing = PairingFactory.getPairing(parameters);

        Element g = pairing.getG1().newRandomElement().getImmutable();
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
}

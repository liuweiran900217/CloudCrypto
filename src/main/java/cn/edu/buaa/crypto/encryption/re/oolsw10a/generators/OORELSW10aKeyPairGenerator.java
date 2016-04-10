package cn.edu.buaa.crypto.encryption.re.oolsw10a.generators;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aPublicKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aKeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aPublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class OORELSW10aKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private OORELSW10aKeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters param) {
        this.parameters = (OORELSW10aKeyPairGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PropertiesParameters parameters = Utils.GeneratePropertiesParameters(this.parameters.getRBitLength(), this.parameters.getQBitLength());
        Pairing pairing =  PairingFactory.getPairing(parameters);
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
                new OORELSW10aPublicKeyParameters(parameters, g, gb, gb2, hb, eggAlpha, this.parameters.getCHEngine()),
                new OORELSW10aMasterSecretKeyParameters(parameters, alpha, b, h));
    }
}

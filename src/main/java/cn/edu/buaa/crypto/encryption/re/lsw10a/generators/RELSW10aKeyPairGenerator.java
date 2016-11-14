package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters revocation encryption public key / master secret key pair generator.
 */
public class RELSW10aKeyPairGenerator implements AsymmetricKeySerPairGenerator {
    private RELSW10aKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters param) {
        this.parameters = (RELSW10aKeyPairGenerationParameter)param;
    }

    public AsymmetricKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();
        Element b2 = b.mulZn(b).getImmutable();

        Element gb = g.powZn(b).getImmutable();
        Element gb2 = g.powZn(b2).getImmutable();
        Element h = pairing.getG1().newRandomElement().getImmutable();
        Element hb = h.powZn(b).getImmutable();

        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        return new AsymmetricKeySerPair(
                new RELSW10aPublicKeySerParameter(this.parameters.getPairingParameters(), g, gb, gb2, hb, eggAlpha),
                new RELSW10aMasterSecretKeySerParameter(this.parameters.getPairingParameters(), alpha, b, h));
    }
}

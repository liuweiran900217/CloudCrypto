package cn.edu.buaa.crypto.signature.pks.bb04;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Boyen signature public key / secret key pair generator.
 */
public class BB04SignKeyPairGenerator implements PairingKeyPairGenerator {
    private BB04SignKeyPairGenerationParameter param;

    public void init(KeyGenerationParameters param) {
        this.param = (BB04SignKeyPairGenerationParameter)param;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(param.getPairingParameters());

        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element g1 = pairing.getG1().newRandomElement().getImmutable();
        Element g2 = pairing.getG2().newRandomElement().getImmutable();
        Element u = g2.powZn(x).getImmutable();
        Element v = g2.powZn(y).getImmutable();
        BB04SignPublicKeySerParameter publicKeyParameters = new BB04SignPublicKeySerParameter(param.getPairingParameters(), g1, g2, u, v);

        return new PairingKeySerPair(
                publicKeyParameters,
                new BB04SignSecretKeySerParameter(param.getPairingParameters(), publicKeyParameters, x, y));
    }
}
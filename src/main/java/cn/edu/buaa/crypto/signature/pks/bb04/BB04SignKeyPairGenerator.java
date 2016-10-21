package cn.edu.buaa.crypto.signature.pks.bb04;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Boyen signature public key / secret key pair generator.
 */
public class BB04SignKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private BB04SignKeyPairGenerationParameters param;

    public void init(KeyGenerationParameters param) {
        this.param = (BB04SignKeyPairGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(param.getPairingParameters());

        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element y = pairing.getZr().newRandomElement().getImmutable();
        Element g1 = pairing.getG1().newRandomElement().getImmutable();
        Element g2 = pairing.getG2().newRandomElement().getImmutable();
        Element u = g2.powZn(x).getImmutable();
        Element v = g2.powZn(y).getImmutable();
        BB04SignPublicKeyParameters publicKeyParameters = new BB04SignPublicKeyParameters(param.getPairingParameters(), g1, g2, u, v);

        return new AsymmetricCipherKeyPair(
                publicKeyParameters,
                new BB04SignSecretKeyParameters(param.getPairingParameters(), publicKeyParameters, x, y));
    }
}
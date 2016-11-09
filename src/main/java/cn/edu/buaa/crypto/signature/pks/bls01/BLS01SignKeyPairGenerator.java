package cn.edu.buaa.crypto.signature.pks.bls01;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Lynn-Shacham signature public key / secret key pair generator.
 */
public class BLS01SignKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private BLS01SignKeyPairGenerationParameters param;

    public void init(KeyGenerationParameters param) {
        this.param = (BLS01SignKeyPairGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.param.getPairingParameters());

        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element v = g.powZn(x).getImmutable();
        BLS01SignPublicKeySerParameter publicKeyParameters = new BLS01SignPublicKeySerParameter(this.param.getPairingParameters(), g, v);

        return new AsymmetricCipherKeyPair(
                publicKeyParameters,
                new BLS01SignSecretKeySerParameter(this.param.getPairingParameters(), x));
    }
}

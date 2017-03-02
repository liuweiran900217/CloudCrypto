package cn.edu.buaa.crypto.signature.pks.bls01;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Lynn-Shacham signature public key / secret key pair generator.
 */
public class BLS01SignKeyPairGenerator implements PairingKeyPairGenerator {
    private BLS01SignKeyPairGenerationParameter param;

    public void init(KeyGenerationParameters param) {
        this.param = (BLS01SignKeyPairGenerationParameter)param;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.param.getPairingParameters());

        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG2().newRandomElement().getImmutable();
        Element v = g.powZn(x).getImmutable();
        BLS01SignPublicPairingKeySerParameter publicKeyParameters = new BLS01SignPublicPairingKeySerParameter(this.param.getPairingParameters(), g, v);

        return new PairingKeySerPair(
                publicKeyParameters,
                new BLS01SignSecretPairingKeySerParameter(this.param.getPairingParameters(), x));
    }
}

package cn.edu.buaa.crypto.signature.pks.bls01;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.signature.pks.PairingSignKeyPairGenerationParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
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
    private PairingSignKeyPairGenerationParameters param;

    public void init(KeyGenerationParameters param) {
        this.param = (PairingSignKeyPairGenerationParameters)param;
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        PairingParameters pairingParameters = PairingUtils.GenerateTypeAParameters(param.getRBitLength(), param.getQBitLength());
        Pairing pairing = PairingFactory.getPairing(pairingParameters);

        Element x = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element v = g.powZn(x).getImmutable();
        BLS01SignPublicKeyParameters publicKeyParameters = new BLS01SignPublicKeyParameters(pairingParameters, g, v);

        return new AsymmetricCipherKeyPair(
                publicKeyParameters,
                new BLS01SignSecretKeyParameters(pairingParameters, x));
    }
}

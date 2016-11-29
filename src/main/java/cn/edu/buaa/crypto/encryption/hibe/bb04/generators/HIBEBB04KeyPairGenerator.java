package cn.edu.buaa.crypto.encryption.hibe.bb04.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Public key / master secret key generator for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04KeyPairGenerator implements PairingKeyPairGenerator {
    private HIBEKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBEKeyPairGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element g1 = g.powZn(alpha).getImmutable();
        Element g2 = pairing.getG1().newRandomElement().getImmutable();
        Element g2Alpha = g2.powZn(alpha).getImmutable();

        Element[] h = new Element[this.parameters.getMaxDepth()];
        for (int i=0; i<this.parameters.getMaxDepth(); i++) {
            h[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        return new PairingKeySerPair(
                new HIBEBB04PublicKeySerParameter(this.parameters.getPairingParameters(), g, g1, g2, h),
                new HIBEBB04MasterSecretKeySerParameter(this.parameters.getPairingParameters(), g2Alpha));
    }
}

package cn.edu.buaa.crypto.encryption.hibe.bbg05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Public Key / Master Secret Key pair generator for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05KeyPairGenerator implements PairingKeyPairGenerator {
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
        Element g3 = pairing.getG1().newRandomElement().getImmutable();
        Element g2Alpha = g2.powZn(alpha).getImmutable();

        Element[] hs = new Element[this.parameters.getMaxDepth()];
        for (int i=0; i<this.parameters.getMaxDepth(); i++) {
            hs[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        return new PairingKeySerPair(
                new HIBEBBG05PublicKeySerParameter(this.parameters.getPairingParameters(), g, g1, g2, g3, hs),
                new HIBEBBG05MasterSecretKeySerParameter(this.parameters.getPairingParameters(), g2Alpha));
    }
}

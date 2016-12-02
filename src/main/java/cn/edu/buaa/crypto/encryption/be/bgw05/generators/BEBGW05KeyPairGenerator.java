package cn.edu.buaa.crypto.encryption.be.bgw05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.genparams.BEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Boneh-Gentry-Waters BE public key / master secret key pair generator.
 */
public class BEBGW05KeyPairGenerator implements PairingKeyPairGenerator {
    private BEKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (BEKeyPairGenerationParameter) keyGenerationParameters;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element gamma = pairing.getZr().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element v = g.powZn(gamma).getImmutable();
        Element[] gs = new Element[this.parameters.getMaxUserNum() * 2 + 1];
        Element alphaI = pairing.getZr().newOneElement().getImmutable();
        for (int i = 1; i < gs.length; i++) {
            alphaI = alphaI.mulZn(alpha).getImmutable();
            if (i == this.parameters.getMaxUserNum() + 1) {
                continue;
            }
            gs[i] = g.powZn(alphaI).getImmutable();
        }

        return new PairingKeySerPair(
                new BEBGW05PublicKeySerParameter(this.parameters.getPairingParameters(), this.parameters.getMaxUserNum(), g, gs, v),
                new BEBGW05MasterSecretKeySerParameter(this.parameters.getPairingParameters(), gamma));
    }
}
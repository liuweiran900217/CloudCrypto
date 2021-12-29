package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * 对应setup
 * Rouselakis-Waters CP-ABE public key / master secret key generator.
 */
public class CPABERW13KeyPairGenerator implements PairingKeyPairGenerator {
    protected CPABEKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameters = (CPABEKeyPairGenerationParameter) keyGenerationParameter;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element u = pairing.getG1().newRandomElement().getImmutable();
        Element h = pairing.getG1().newRandomElement().getImmutable();
        Element w = pairing.getG1().newRandomElement().getImmutable();
        Element v = pairing.getG1().newRandomElement().getImmutable();
        Element f = pairing.getG1().newRandomElement().getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        return new PairingKeySerPair(
                new CPABERW13PublicKeySerParameter(this.parameters.getPairingParameters(), g, u, h, w, v, f, eggAlpha),
                new CPABERW13MasterSecretKeySerParameter(this.parameters.getPairingParameters(), alpha));
    }
}
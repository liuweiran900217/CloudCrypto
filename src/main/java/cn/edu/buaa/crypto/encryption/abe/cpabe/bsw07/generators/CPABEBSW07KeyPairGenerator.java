package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams.CPABEBSW07KeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Administrator on 2016/11/20.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE public key / master secret key pair generator.
 */
public class CPABEBSW07KeyPairGenerator implements PairingKeyPairGenerator {
    private CPABEBSW07KeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameters = (CPABEBSW07KeyPairGenerationParameter) keyGenerationParameter;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element gAlpha = g.powZn(alpha).getImmutable();
        Element h = g.powZn(beta).getImmutable();
        Element f = g.powZn(beta.invert()).getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        return new PairingKeySerPair(
                new CPABEBSW07PublicKeySerParameter(this.parameters.getPairingParameters(), g, h, f, eggAlpha),
                new CPABEBSW07MasterSecretKeySerParameter(this.parameters.getPairingParameters(), gAlpha, beta));
    }
}
package cn.edu.buaa.crypto.encryption.ibe.gen06b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.IBEGen06bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.IBEGen06bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Gentry CCA2-secure IBE public key / master secret key generator.
 */
public class IBEGen06bKeyPairGenerator implements PairingKeyPairGenerator {
    private IBEKeyPairGenerationParameter params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = (IBEKeyPairGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.params.getPairingParameters());
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element g1 = g.powZn(alpha).getImmutable();
        Element h = pairing.getG1().newRandomElement().getImmutable();
        Element h2 = pairing.getG1().newRandomElement().getImmutable();
        Element h3 = pairing.getG1().newRandomElement().getImmutable();

        return new PairingKeySerPair(
                new IBEGen06bPublicKeySerParameter(this.params.getPairingParameters(), g, g1, h, h2, h3),
                new IBEGen06bMasterSecretKeySerParameter(this.params.getPairingParameters(), alpha));
    }
}
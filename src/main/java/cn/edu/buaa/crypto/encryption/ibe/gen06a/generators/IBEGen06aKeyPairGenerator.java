package cn.edu.buaa.crypto.encryption.ibe.gen06a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEKeyPairGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CPA-secure IBE public key / master secret key pair generator.
 */
public class IBEGen06aKeyPairGenerator implements PairingKeyPairGenerator {
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

        return new PairingKeySerPair(
                new IBEGen06aPublicKeySerParameter(this.params.getPairingParameters(), g, g1, h),
                new IBEGen06aMasterSecretKeySerParameter(this.params.getPairingParameters(), alpha));
    }
}

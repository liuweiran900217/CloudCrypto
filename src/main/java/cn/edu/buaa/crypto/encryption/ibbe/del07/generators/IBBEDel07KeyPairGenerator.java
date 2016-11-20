package cn.edu.buaa.crypto.encryption.ibbe.del07.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.ibbe.del07.genparams.IBBEDel07KeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Public key / master secret key generator for Delerablée IBBE scheme.
 */
public class IBBEDel07KeyPairGenerator implements PairingKeyPairGenerator {
    private IBBEDel07KeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (IBBEDel07KeyPairGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());
        Element[] hs = new Element[this.parameters.getMaxBroadcastReceiver() + 1];
        hs[0] = pairing.getG2().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element gamma = pairing.getZr().newRandomElement().getImmutable();
        Element w = g.powZn(gamma).getImmutable();
        Element v = pairing.pairing(g, hs[0]).getImmutable();
        Element gammaToi = pairing.getZr().newOneElement();

        for (int i = 1; i < hs.length; i++) {
            gammaToi = gammaToi.mulZn(gamma).getImmutable();
            hs[i] = hs[0].powZn(gammaToi).getImmutable();
        }

        return new PairingKeySerPair(
                new IBBEDel07PublicKeySerParameter(this.parameters.getPairingParameters(), w, v, hs),
                new IBBEDel07MasterSecretKeySerParameter(this.parameters.getPairingParameters(), g, gamma));
    }
}

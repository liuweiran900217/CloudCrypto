package cn.edu.buaa.crypto.encryption.ibbe.del07.generators;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07KeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.ibbe.del07.params.IBBEDel07PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Public key / master secret key generator for Delerablée IBBE scheme.
 */
public class IBBEDel07KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private IBBEDel07KeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (IBBEDel07KeyPairGenerationParameters)keyGenerationParameters;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PropertiesParameters parameters = PairingUtils.GenerateTypeAParameters(this.parameters.getRBitLength(), this.parameters.getQBitLength());
        Pairing pairing = PairingFactory.getPairing(parameters);
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

        return new AsymmetricCipherKeyPair(
                new IBBEDel07PublicKeyParameters(parameters, w, v, hs),
                new IBBEDel07MasterSecretKeyParameters(parameters, g, gamma));
    }
}

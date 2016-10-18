package cn.edu.buaa.crypto.encryption.hibe.bbg05.generators;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05KeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Public Key / Master Secret Key pair generator for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private HIBEBBG05KeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBEBBG05KeyPairGenerationParameters)keyGenerationParameters;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PropertiesParameters parameters = PairingUtils.GenerateTypeAParameters(this.parameters.getRBitLength(), this.parameters.getQBitLength());
        Pairing pairing = PairingFactory.getPairing(parameters);

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

        return new AsymmetricCipherKeyPair(
                new HIBEBBG05PublicKeyParameters(parameters, g, g1, g2, g3, hs),
                new HIBEBBG05MasterSecretKeyParameters(parameters, g2Alpha));
    }
}

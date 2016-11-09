package cn.edu.buaa.crypto.encryption.hibe.bb04.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04KeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Public key / master secret key generator for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private HIBEBB04KeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBEBB04KeyPairGenerationParameters)keyGenerationParameters;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PropertiesParameters parameters = PairingUtils.GenerateTypeAParameters(this.parameters.getRBitLength(), this.parameters.getQBitLength());
        Pairing pairing = PairingFactory.getPairing(parameters);

        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element g1 = g.powZn(alpha).getImmutable();
        Element g2 = pairing.getG1().newRandomElement().getImmutable();
        Element g2Alpha = g2.powZn(alpha).getImmutable();

                Element[] h = new Element[this.parameters.getMaxDepth()];
        for (int i=0; i<this.parameters.getMaxDepth(); i++) {
            h[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        return new AsymmetricCipherKeyPair(
                new HIBEBB04PublicKeySerParameter(parameters, g, g1, g2, h),
                new HIBEBB04MasterSecretKeySerParameter(parameters, g2Alpha));
    }
}

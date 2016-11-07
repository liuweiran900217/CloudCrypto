package cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.params.HIBBELLW16aKeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.params.HIBBELLW16aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.params.HIBBELLW16aPublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE ciphertext / session key pair generator.
 */
public class HIBBELLW16aKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private HIBBELLW16aKeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBBELLW16aKeyPairGenerationParameters)keyGenerationParameters;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PropertiesParameters parameters = (PropertiesParameters) this.parameters.getPairingParameters();
        Pairing pairing = PairingFactory.getPairing(parameters);

        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element g1 = g.powZn(alpha).getImmutable();
        Element g2 = pairing.getG1().newRandomElement().getImmutable();
        Element g3 = pairing.getG1().newRandomElement().getImmutable();
        Element g2Alpha = g2.powZn(alpha).getImmutable();
        Element[] u = new Element[this.parameters.getMaxUser()];
        for (int i=0; i<u.length; i++) {
            u[i] = pairing.getG1().newRandomElement().getImmutable();
        }

        return new AsymmetricCipherKeyPair(
                new HIBBELLW16aPublicKeyParameters(parameters, g, g1, g2, g3, u),
                new HIBBELLW16aMasterSecretKeyParameters(parameters, g2Alpha));
    }
}

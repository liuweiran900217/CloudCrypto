package cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE ciphertext / session key pair generator.
 */
public class HIBBELLW16aKeyPairGenerator implements PairingKeyPairGenerator {
    private HIBBEKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBBEKeyPairGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerPair generateKeyPair() {
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

        return new PairingKeySerPair(
                new HIBBELLW16aPublicKeySerParameter(parameters, g, g1, g2, g3, u),
                new HIBBELLW16aMasterSecretKeySerParameter(parameters, g2Alpha));
    }
}

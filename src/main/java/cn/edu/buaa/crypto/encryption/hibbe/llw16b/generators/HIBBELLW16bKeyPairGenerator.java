package cn.edu.buaa.crypto.encryption.hibbe.llw16b.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams.HIBBELLW16bKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Signer;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE public key / master secret key generator.
 */
public class HIBBELLW16bKeyPairGenerator implements AsymmetricKeySerPairGenerator {
    private HIBBELLW16bKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBBELLW16bKeyPairGenerationParameter)keyGenerationParameters;
    }

    public AsymmetricKeySerPair generateKeyPair() {
        Signer signer= this.parameters.getSigner();
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
        Element uv = pairing.getG1().newRandomElement().getImmutable();

        return new AsymmetricKeySerPair(
                new HIBBELLW16bPublicKeySerParameter(parameters, signer, g, g1, g2, g3, u, uv),
                new HIBBELLW16bMasterSecretKeySerParameter(parameters, g2Alpha));
    }
}

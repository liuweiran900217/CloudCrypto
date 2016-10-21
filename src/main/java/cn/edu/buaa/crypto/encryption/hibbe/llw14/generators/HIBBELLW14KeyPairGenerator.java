package cn.edu.buaa.crypto.encryption.hibbe.llw14.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14KeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE public key / master secret key generator.
 */
public class HIBBELLW14KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private HIBBELLW14KeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBBELLW14KeyPairGenerationParameters)keyGenerationParameters;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PropertiesParameters parameters = PairingUtils.GenerateTypeA1Parameters(this.parameters.getQBitLength());
        Pairing pairing = PairingFactory.getPairing(parameters);
        Element generator = pairing.getG1().newRandomElement().getImmutable();

        Element g = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element gAlpha = g.powZn(alpha).getImmutable();
        Element h = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        Element X3 = ElementUtils.getGenerator(pairing, generator, parameters, 2, 3).getImmutable();
        Element[] u = new Element[this.parameters.getMaxUser()];
        for (int i=0; i<u.length; i++) {
            u[i] = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        }
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        // Remove factorization from curveParams
        parameters.remove("n0");
        parameters.remove("n1");
        parameters.remove("n2");
        return new AsymmetricCipherKeyPair(
                new HIBBELLW14PublicKeyParameters(parameters, g, h, u, X3, eggAlpha),
                new HIBBELLW14MasterSecretKeyParameters(parameters, gAlpha));
    }
}

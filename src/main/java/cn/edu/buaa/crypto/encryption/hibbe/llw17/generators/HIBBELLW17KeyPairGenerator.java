package cn.edu.buaa.crypto.encryption.hibbe.llw17.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams.HIBBELLW17KeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE public key / master secret key pair generator.
 */
public class HIBBELLW17KeyPairGenerator implements AsymmetricKeySerPairGenerator {
    private HIBBELLW17KeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (HIBBELLW17KeyPairGenerationParameter)keyGenerationParameters;
    }

    public AsymmetricKeySerPair generateKeyPair() {
        PropertiesParameters parameters = (PropertiesParameters) this.parameters.getPairingParameters();
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
        Element uv = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        // Remove factorization from curveParams
        parameters.remove("n0");
        parameters.remove("n1");
        parameters.remove("n2");
        return new AsymmetricKeySerPair(
                new HIBBELLW17PublicKeySerParameter(parameters, g, h, u, uv, X3, eggAlpha),
                new HIBBELLW17MasterSecretKeySerParameter(parameters, gAlpha));
    }
}

package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10KeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/7.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10KeyPairGenerator implements AsymmetricKeySerPairGenerator {
    private IBELW10KeyPairGenerationParameter params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = (IBELW10KeyPairGenerationParameter)keyGenerationParameters;
    }

    public AsymmetricKeySerPair generateKeyPair() {
        PropertiesParameters parameters = (PropertiesParameters) this.params.getPairingParameters();
        Pairing pairing = PairingFactory.getPairing(parameters);
        Element generator = pairing.getG1().newRandomElement().getImmutable();

        Element g = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element u = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        Element h = ElementUtils.getGenerator(pairing, generator, parameters, 0, 3).getImmutable();
        Element g3Generator = ElementUtils.getGenerator(pairing, generator, parameters, 2, 3).getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        // Remove factorization from curveParams
        parameters.remove("n0");
        parameters.remove("n1");
        parameters.remove("n2");
        return new AsymmetricKeySerPair(
                new IBELW10PublicKeySerParameter(parameters, u, g, h, eggAlpha),
                new IBELW10MasterSecretKeySerParameter(parameters, alpha, g3Generator));
    }
}

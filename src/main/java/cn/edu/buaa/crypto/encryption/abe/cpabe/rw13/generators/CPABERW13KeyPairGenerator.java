package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13KeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Public Key / Master Secret Key pair generator for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private CPABERW13KeyPairGenerationParameters parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (CPABERW13KeyPairGenerationParameters)keyGenerationParameters;
    }

    public AsymmetricCipherKeyPair generateKeyPair() {
        PropertiesParameters parameters = PairingUtils.GenerateTypeAParameters(this.parameters.getRBitLength(), this.parameters.getQBitLength());
        Pairing pairing = PairingFactory.getPairing(parameters);

        Element g = pairing.getG1().newRandomElement().getImmutable();
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element u = g.powZn(alpha).getImmutable();
        Element h = pairing.getG1().newRandomElement().getImmutable();
        Element w = pairing.getG1().newRandomElement().getImmutable();
        Element v = pairing.getG1().newRandomElement().getImmutable();
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        return new AsymmetricCipherKeyPair(
                new CPABERW13PublicKeySerParameter(parameters, g, u, h, w, v, eggAlpha, this.parameters.getAccessControlEngine()),
                new CPABERW13MasterSecretKeySerParameter(parameters, alpha));
    }
}

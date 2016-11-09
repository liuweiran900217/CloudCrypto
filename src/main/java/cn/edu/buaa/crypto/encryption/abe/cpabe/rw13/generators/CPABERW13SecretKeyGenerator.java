package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13SecretKeyGenerationParameters;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Secret Key generator for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13SecretKeyGenerator {
    private CPABERW13SecretKeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = (CPABERW13SecretKeyGenerationParameters)keyGenerationParameters;
    }

    public CipherParameters generateKey() {
        CPABERW13PublicKeySerParameter publicKeyParameters = params.getPublicKeyParameters();
        CPABERW13MasterSecretKeySerParameter masterSecretKeyParameters = params.getMasterSecretKeyParameters();
        int length = params.getLength();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementAttributes = PairingUtils.MapToZr(pairing, params.getAttributes());
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element[] rs = new Element[length];
        for (int i = 0; i < rs.length; i++) {
            rs[i] = pairing.getZr().newRandomElement().getImmutable();
        }

        Element k0 = publicKeyParameters.getG().powZn(masterSecretKeyParameters.getAlpha())
                .mul(publicKeyParameters.getW().powZn(r)).getImmutable();
        Element k1 = publicKeyParameters.getG().powZn(r).getImmutable();

        Element[] k2s = new Element[length];
        Element[] k3s = new Element[length];

        for (int i = 0; i < length; i++) {
            k2s[i] = publicKeyParameters.getG().powZn(rs[i]);
            k3s[i] = publicKeyParameters.getU().powZn(elementAttributes[i]).mul(publicKeyParameters.getH()).powZn(rs[i])
                    .mul(publicKeyParameters.getV().powZn(r.negate())).getImmutable();
        }

        return new CPABERW13SecretKeySerParameter(publicKeyParameters.getParameters(),
                params.getAttributes(), elementAttributes, k0, k1, k2s, k3s);
    }
}

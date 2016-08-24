package cn.edu.buaa.crypto.encryption.re.oolsw10a.generators;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.OORELSW10aEngine;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aPublicKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aSecretKeyGenerationParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aSecretKeyParameters;
import it.unisa.dia.gas.crypto.cipher.CipherParametersGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/7.
 */
public class OORELSW10aSecretKeyGenerator implements CipherParametersGenerator {

    private KeyGenerationParameters keyGenerationParameters;


    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.keyGenerationParameters = keyGenerationParameters;
    }

    public CipherParameters generateKey() {
        if (keyGenerationParameters instanceof OORELSW10aSecretKeyGenerationParameters) {
            OORELSW10aSecretKeyGenerationParameters parameters = (OORELSW10aSecretKeyGenerationParameters)keyGenerationParameters;
            OORELSW10aMasterSecretKeyParameters masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();
            OORELSW10aPublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            Element elementId = PairingUtils.MapToFirstHalfZr(pairing, parameters.getId()).getImmutable();
            Element t = pairing.getZr().newRandomElement().getImmutable();

            Element d0 = publicKeyParameters.getG().powZn(masterSecretKeyParameters.getAlpha())
                    .mul(publicKeyParameters.getGb2().powZn(t)).getImmutable();
            Element d1 = publicKeyParameters.getGb().powZn(elementId).mul(masterSecretKeyParameters.getH()).powZn(t).getImmutable();
            Element d2 = publicKeyParameters.getG().powZn(t.negate()).getImmutable();
            return new OORELSW10aSecretKeyParameters(publicKeyParameters.getParameters(), parameters.getId(), elementId, d0, d1, d2);

        } else {
            throw new IllegalArgumentException
                    ("Invalid KeyGenerationParameters for " + OORELSW10aEngine.SCHEME_NAME + " Secret Key Generatation, find "
                            + this.keyGenerationParameters.getClass().getName() + ", require "
                            + OORELSW10aSecretKeyGenerationParameters.class.getName());
        }
    }
}

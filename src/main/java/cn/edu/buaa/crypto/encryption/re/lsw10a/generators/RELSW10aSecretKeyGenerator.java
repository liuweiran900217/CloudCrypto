package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.re.lsw10a.RELSW10aEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aPublicKeyParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aSecretKeyGenerationParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aSecretKeyParameters;
import it.unisa.dia.gas.crypto.cipher.CipherParametersGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class RELSW10aSecretKeyGenerator implements CipherParametersGenerator {
    private KeyGenerationParameters keyGenerationParameters;


    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.keyGenerationParameters = keyGenerationParameters;
    }

    public CipherParameters generateKey() {
        if (keyGenerationParameters instanceof RELSW10aSecretKeyGenerationParameters) {
            RELSW10aSecretKeyGenerationParameters parameters = (RELSW10aSecretKeyGenerationParameters)keyGenerationParameters;
            RELSW10aMasterSecretKeyParameters masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();
            RELSW10aPublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            Element elementId = PairingUtils.MapToZr(pairing, parameters.getId()).getImmutable();
            Element t = pairing.getZr().newRandomElement().getImmutable();

            Element d0 = publicKeyParameters.getG().powZn(masterSecretKeyParameters.getAlpha())
                    .mul(publicKeyParameters.getGb2().powZn(t)).getImmutable();
            Element d1 = publicKeyParameters.getGb().powZn(elementId).mul(masterSecretKeyParameters.getH()).powZn(t).getImmutable();
            Element d2 = publicKeyParameters.getG().powZn(t.negate()).getImmutable();
            return new RELSW10aSecretKeyParameters(publicKeyParameters.getParameters(), parameters.getId(), elementId, d0, d1, d2);

        } else {
            throw new IllegalArgumentException
                    ("Invalid KeyGenerationParameters for " + RELSW10aEngine.SCHEME_NAME + " Secret Key Generatation, find "
                            + this.keyGenerationParameters.getClass().getName() + ", require "
                            + RELSW10aSecretKeyGenerationParameters.class.getName());
        }
    }
}

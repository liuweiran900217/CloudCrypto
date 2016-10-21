package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10SecretKeyGenerationParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10SecretKeyParameters;
import it.unisa.dia.gas.crypto.cipher.CipherParametersGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/7.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10SecretKeyGenerator implements CipherParametersGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public CipherParameters generateKey() {
        IBELW10SecretKeyGenerationParameters parameters = (IBELW10SecretKeyGenerationParameters)params;

        IBELW10MasterSecretKeyParameters masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();
        IBELW10PublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementId = PairingUtils.MapToZr(pairing, parameters.getId()).getImmutable();
        Element Zr_R3 = pairing.getZr().newRandomElement().getImmutable();
        Element R3 = masterSecretKeyParameters.getG3Generator().powZn(Zr_R3).getImmutable();
        Element Zr_R3Prime = pairing.getZr().newRandomElement().getImmutable();
        Element R3Prime = masterSecretKeyParameters.getG3Generator().powZn(Zr_R3Prime).getImmutable();
        Element r = pairing.getZr().newRandomElement().getImmutable();

        //Compute k1
        Element k1 = publicKeyParameters.getG().powZn(r).mul(R3).getImmutable();
        //Compute k2
        Element k2 = publicKeyParameters.getG().powZn(masterSecretKeyParameters.getAlpha())
                .mul(publicKeyParameters.getU().powZn(elementId).mul(publicKeyParameters.getH()).powZn(r))
                .mul(R3Prime).getImmutable();
            return new IBELW10SecretKeyParameters(publicKeyParameters.getParameters(), parameters.getId(), elementId, k1, k2);
        }
}

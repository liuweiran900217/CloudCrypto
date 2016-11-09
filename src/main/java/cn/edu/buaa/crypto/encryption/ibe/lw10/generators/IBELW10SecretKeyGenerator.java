package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerParametersGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10SecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/7.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10SecretKeyGenerator implements AsymmetricKeySerParametersGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public AsymmetricKeySerParameter generateKey() {
        IBELW10SecretKeyGenerationParameter parameters = (IBELW10SecretKeyGenerationParameter)params;

        IBELW10MasterSecretKeySerParameter masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();
        IBELW10PublicKeySerParameter publicKeyParameters = parameters.getPublicKeyParameters();

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
            return new IBELW10SecretKeySerParameter(publicKeyParameters.getParameters(), parameters.getId(), elementId, k1, k2);
        }
}

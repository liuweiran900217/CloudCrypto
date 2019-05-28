package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/5/7.
 *
 * Lewko-Waters secret key generator.
 */
public class IBELW10SecretKeyGenerator implements PairingKeyParameterGenerator {
    private IBESecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (IBESecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        IBELW10MasterSecretKeySerParameter masterSecretKeyParameters = (IBELW10MasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        IBELW10PublicKeySerParameter publicKeyParameters = (IBELW10PublicKeySerParameter)parameters.getPublicKeyParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.Zr).getImmutable();
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

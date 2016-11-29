package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.genparams.RESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters secret key generator.
 */
public class RELSW10aSecretKeyGenerator implements PairingKeyParameterGenerator {
    private RESecretKeyGenerationParameter parameters;


    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (RESecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        RELSW10aMasterSecretKeySerParameter masterSecretKeyParameters = (RELSW10aMasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        RELSW10aPublicKeySerParameter publicKeyParameters = (RELSW10aPublicKeySerParameter)parameters.getPublicKeyParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.Zr).getImmutable();
        Element t = pairing.getZr().newRandomElement().getImmutable();

        Element d0 = publicKeyParameters.getG().powZn(masterSecretKeyParameters.getAlpha())
                .mul(publicKeyParameters.getGb2().powZn(t)).getImmutable();
        Element d1 = publicKeyParameters.getGb().powZn(elementId).mul(masterSecretKeyParameters.getH()).powZn(t).getImmutable();
        Element d2 = publicKeyParameters.getG().powZn(t.negate()).getImmutable();
        return new RELSW10aSecretKeySerParameter(publicKeyParameters.getParameters(), parameters.getId(), elementId, d0, d1, d2);
    }
}

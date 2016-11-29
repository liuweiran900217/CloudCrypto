package cn.edu.buaa.crypto.encryption.ibbe.del07.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.genparams.IBBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Secret key generator for Delerablée IBBE scheme.
 */
public class IBBEDel07SecretKeyGenerator implements PairingKeyParameterGenerator {
    private IBBESecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (IBBESecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        IBBEDel07MasterSecretKeySerParameter masterSecretKeyParameters = (IBBEDel07MasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        IBBEDel07PublicKeySerParameter publicKeyParameters = (IBBEDel07PublicKeySerParameter)parameters.getPublicKeyParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.Zr);

        Element secretKey = masterSecretKeyParameters.getG().powZn(masterSecretKeyParameters.getGamma().add(elementId).invert()).getImmutable();

        return new IBBEDel07SecretKeySerParameter(publicKeyParameters.getParameters(), parameters.getId(), elementId, secretKey);
    }
}

package cn.edu.buaa.crypto.encryption.ibe.bf01a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE secret key generator.
 */
public class IBEBF01aSecretKeyGenerator implements PairingKeyParameterGenerator {
    private IBESecretKeyGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = (IBESecretKeyGenerationParameter)keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        IBEBF01aMasterSecretKeySerParameter masterSecretKeyParameters = (IBEBF01aMasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
        IBEBF01aPublicKeySerParameter publicKeyParameters = (IBEBF01aPublicKeySerParameter)parameters.getPublicKeyParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.G1).getImmutable();
        Element d = elementId.powZn(masterSecretKeyParameters.getS()).getImmutable();
        return new IBEBF01aSecretKeySerParameter(publicKeyParameters.getParameters(), parameters.getId(), elementId, d);
    }
}

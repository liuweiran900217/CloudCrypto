package cn.edu.buaa.crypto.encryption.hibe.bbg05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEDelegateGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key Generators for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05SecretKeyGenerator implements PairingKeyParameterGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        if (params instanceof HIBESecretKeyGenerationParameter) {
            HIBESecretKeyGenerationParameter parameters = (HIBESecretKeyGenerationParameter)params;

            HIBEBBG05PublicKeySerParameter publicKeyParameters = (HIBEBBG05PublicKeySerParameter)parameters.getPublicKeyParameter();
            HIBEBBG05MasterSecretKeySerParameter masterSecretKeyParameters = (HIBEBBG05MasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
            int length = parameters.getLength();
            assert(length <= publicKeyParameters.getMaxLength());

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, parameters.getIds(), PairingUtils.PairingGroupType.Zr);
            Element r = pairing.getZr().newRandomElement().getImmutable();
            Element a0 = publicKeyParameters.getG3().getImmutable();
            Element a1 = publicKeyParameters.getG().powZn(r).getImmutable();
            Element[] hs = new Element[publicKeyParameters.getMaxLength()];

            for (int i=0; i<publicKeyParameters.getMaxLength(); i++){
                if (i < parameters.getLength()) {
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getHsAt(i).powZn(elementIds[i])).getImmutable();
                    //Set h[i] to be one
                    hs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    //Set h[i] to be h_i^r
                    hs[i] = publicKeyParameters.getHsAt(i).powZn(r).getImmutable();
                }
            }
            //raise a0 to the power of r and then multiple it by g2Alpha
            a0 = a0.powZn(r).mul(masterSecretKeyParameters.getG2Alpha()).getImmutable();

            return new HIBEBBG05SecretKeySerParameter(publicKeyParameters.getParameters(),
                    parameters.getIds(), elementIds, a0, a1, hs);
        } else if (params instanceof HIBEDelegateGenerationParameter)  {
            HIBEDelegateGenerationParameter parameters = (HIBEDelegateGenerationParameter)params;

            HIBEBBG05PublicKeySerParameter publicKeyParameters = (HIBEBBG05PublicKeySerParameter)parameters.getPublicKeyParameter();
            HIBEBBG05SecretKeySerParameter secretKeyParameters = (HIBEBBG05SecretKeySerParameter)parameters.getSecretKeyParameter();
            int length = secretKeyParameters.getLength() + 1;
            assert(length <= publicKeyParameters.getMaxLength());

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String[] ids = new String[length];
            Element[] elementIds = new Element[length];
            Element elementDelegateId = PairingUtils.MapStringToGroup(pairing, parameters.getDelegateId(), PairingUtils.PairingGroupType.Zr).getImmutable();
            Element r = pairing.getZr().newRandomElement().getImmutable();
            Element a0 = publicKeyParameters.getG3().getImmutable();
            Element a1 = publicKeyParameters.getG().powZn(r).getImmutable();
            Element[] hs = new Element[publicKeyParameters.getMaxLength()];

            for (int i=0; i<publicKeyParameters.getMaxLength(); i++) {
                if (i < length - 1) {
                    ids[i] = secretKeyParameters.getIdAt(i);
                    elementIds[i] = secretKeyParameters.getElementIdAt(i);
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getHsAt(i).powZn(elementIds[i])).getImmutable();
                    //Set h[i] to be one
                    hs[i] = pairing.getG1().newOneElement().getImmutable();
                } else if (i == length - 1) {
                    ids[i] = parameters.getDelegateId();
                    elementIds[i] = elementDelegateId;
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getHsAt(i).powZn(elementIds[i]))
                            .powZn(r)
                            .mul(secretKeyParameters.getA0())
                            .mul(secretKeyParameters.getBsAt(i).powZn(elementIds[i])).getImmutable();
                    //Compute a1
                    a1 = a1.mul(secretKeyParameters.getA1()).getImmutable();
                    //Set h[i] to be one
                    hs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {

                    hs[i] = secretKeyParameters.getBsAt(i)
                            .mul(publicKeyParameters.getHsAt(i).powZn(r)).getImmutable();
                }
            }
            return new HIBEBBG05SecretKeySerParameter(publicKeyParameters.getParameters(),
                    ids, elementIds, a0, a1, hs);
        } else {
            PairingUtils.NotVerifyCipherParameterInstance(HIBEBBG05Engine.SCHEME_NAME, params,
                    HIBESecretKeyGenerationParameter.class.getName() + " or "
                            + HIBEDelegateGenerationParameter.class.getName());
            return null;
        }
    }
}

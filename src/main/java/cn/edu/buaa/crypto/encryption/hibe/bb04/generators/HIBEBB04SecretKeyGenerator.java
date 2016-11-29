package cn.edu.buaa.crypto.encryption.hibe.bb04.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEDelegateGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Secret key generator for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04SecretKeyGenerator implements PairingKeyParameterGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        if (params instanceof HIBESecretKeyGenerationParameter) {
            HIBESecretKeyGenerationParameter parameters = (HIBESecretKeyGenerationParameter)params;

            HIBEBB04MasterSecretKeySerParameter masterSecretKeyParameters = (HIBEBB04MasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
            HIBEBB04PublicKeySerParameter publicKeyParameters = (HIBEBB04PublicKeySerParameter)parameters.getPublicKeyParameter();
            int length = parameters.getLength();
            assert(length <= publicKeyParameters.getMaxDepth());

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, parameters.getIds(), PairingUtils.PairingGroupType.Zr);
            Element[] rs = new Element[length];
            Element[] ds = new Element[length];
            Element d0 = pairing.getG1().newOneElement();
            d0 = d0.mul(masterSecretKeyParameters.getG2Alpha());

            for (int i = 0; i < rs.length; i++){
                rs[i] = pairing.getZr().newRandomElement().getImmutable();
                ds[i] = publicKeyParameters.getG().powZn(rs[i]).getImmutable();
                d0 = d0.mul(publicKeyParameters.getG1().powZn(elementIds[i]).mul(publicKeyParameters.getHsAt(i)).powZn(rs[i])).getImmutable();
            }

            return new HIBEBB04SecretKeySerParameter(publicKeyParameters.getParameters(), parameters.getIds(), elementIds, d0, ds);
        } else if (params instanceof HIBEDelegateGenerationParameter)  {
            HIBEDelegateGenerationParameter parameters = (HIBEDelegateGenerationParameter)params;

            HIBEBB04PublicKeySerParameter publicKeyParameters = (HIBEBB04PublicKeySerParameter)parameters.getPublicKeyParameter();
            HIBEBB04SecretKeySerParameter secretKeyParameters = (HIBEBB04SecretKeySerParameter)parameters.getSecretKeyParameter();
            int length = secretKeyParameters.getLength() + 1;
            assert(length <= publicKeyParameters.getMaxDepth());

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String[] ids = new String[length];
            Element[] elementIds = new Element[length];
            Element[] ds = new Element[length];

            Element elementDelegateId = PairingUtils.MapStringToGroup(pairing, parameters.getDelegateId(), PairingUtils.PairingGroupType.Zr).getImmutable();
            Element r_j = pairing.getZr().newRandomElement().getImmutable();
            Element d_j = publicKeyParameters.getG().powZn(r_j).getImmutable();
            Element d0 = secretKeyParameters.getD0();
            d0 = d0.mul(publicKeyParameters.getG1().powZn(elementDelegateId).mul(publicKeyParameters.getHsAt(length - 1)).powZn(r_j)).getImmutable();
            for (int i = 0; i < length - 1; i++) {
                ids[i] = secretKeyParameters.getIdAt(i);
                elementIds[i] = secretKeyParameters.getElementIdAt(i);
                ds[i] = secretKeyParameters.getDsAt(i);
            }
            ids[length - 1] = parameters.getDelegateId();
            elementIds[length - 1] = elementDelegateId;
            ds[length - 1] = d_j;

            return new HIBEBB04SecretKeySerParameter(publicKeyParameters.getParameters(), ids, elementIds, d0, ds);
        } else {
            throw new IllegalArgumentException
                    ("Invalid KeyGenerationParameters for HIBEBB04Engine Secret Key Generatation, find "
                            + params.getClass().getName() + ", require "
                            + HIBESecretKeyGenerationParameter.class.getName() + " or "
                            + HIBEDelegateGenerationParameter.class.getName());
        }
    }
}

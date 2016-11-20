package cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams.HIBBELLW16aDelegateGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams.HIBBELLW16aSecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.HIBBELLW16aEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE secret key generator.
 */
public class HIBBELLW16aSecretKeyGenerator implements PairingKeyParameterGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        if (params instanceof HIBBELLW16aSecretKeyGenerationParameter) {
            HIBBELLW16aSecretKeyGenerationParameter parameters = (HIBBELLW16aSecretKeyGenerationParameter)params;

            HIBBELLW16aPublicKeySerParameter publicKeyParameters = (HIBBELLW16aPublicKeySerParameter)parameters.getPublicKeyParameter();
            HIBBELLW16aMasterSecretKeySerParameter masterSecretKeyParameters = (HIBBELLW16aMasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
            if (parameters.getIds().length != publicKeyParameters.getMaxUser()) {
                throw new IllegalArgumentException("Invalid identity vector length");
            }

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, parameters.getIds(), PairingUtils.PairingGroupType.Zr);
            Element r = pairing.getZr().newRandomElement().getImmutable();

            Element a1 = publicKeyParameters.getG().powZn(r).getImmutable();
            Element a0 = publicKeyParameters.getG3().getImmutable();
            Element[] bs = new Element[publicKeyParameters.getMaxUser()];

            for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
                if (parameters.getIdAt(i) != null) {
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    //Set h[i] to be h_i^r
                    bs[i] = publicKeyParameters.getUsAt(i).powZn(r).getImmutable();
                }
            }
            //raise a0 to the power of r and then multiple it by gAlpha
            a0 = a0.powZn(r).mul(masterSecretKeyParameters.getG2Alpha()).getImmutable();

            return new HIBBELLW16aSecretKeySerParameter(publicKeyParameters.getParameters(),
                    parameters.getIds(), elementIds, a0, a1, bs);
        } else if (params instanceof HIBBELLW16aDelegateGenerationParameter)  {
            HIBBELLW16aDelegateGenerationParameter parameters = (HIBBELLW16aDelegateGenerationParameter)params;

            HIBBELLW16aPublicKeySerParameter publicKeyParameters = (HIBBELLW16aPublicKeySerParameter)parameters.getPublicKeyParameter();
            HIBBELLW16aSecretKeySerParameter secretKeyParameters = (HIBBELLW16aSecretKeySerParameter)parameters.getSecretKeyParameter();
            if (secretKeyParameters.getIds().length != publicKeyParameters.getMaxUser()
                    || secretKeyParameters.getIds()[parameters.getIndex()] != null) {
                throw new IllegalArgumentException("Invalid identity vector length");
            }

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String[] ids = new String[publicKeyParameters.getMaxUser()];
            Element[] elementIds = new Element[publicKeyParameters.getMaxUser()];
            Element elementDelegateId = PairingUtils.MapStringToGroup(pairing, parameters.getDelegateId(), PairingUtils.PairingGroupType.Zr).getImmutable();

            Element t = pairing.getZr().newRandomElement().getImmutable();
            Element a0 = publicKeyParameters.getG3().getImmutable();
            Element a1 = publicKeyParameters.getG().powZn(t).getImmutable();
            Element[] bs = new Element[publicKeyParameters.getMaxUser()];

            for (int i=0; i<publicKeyParameters.getMaxUser(); i++) {
                if (secretKeyParameters.getIdAt(i) != null) {
                    ids[i] = secretKeyParameters.getIdAt(i);
                    elementIds[i] = secretKeyParameters.getElementIdAt(i);
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else if (i == parameters.getIndex()) {
                    ids[i] = parameters.getDelegateId();
                    elementIds[i] = elementDelegateId;
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    bs[i] = secretKeyParameters.getBsAt(i)
                            .mul(publicKeyParameters.getUsAt(i).powZn(t)).getImmutable();
                }
            }
            //Compute the rest of a0
            a0 = a0.powZn(t).mul(secretKeyParameters.getA0())
                    .mul(secretKeyParameters.getBsAt(parameters.getIndex()).powZn(elementIds[parameters.getIndex()])).getImmutable();
            //Compute the result of a1
            a1 = a1.mul(secretKeyParameters.getA1()).getImmutable();

            return new HIBBELLW16aSecretKeySerParameter(publicKeyParameters.getParameters(),
                    ids, elementIds, a0, a1, bs);
        } else {
            throw new IllegalArgumentException
                    ("Invalid KeyGenerationParameters for " + HIBBELLW16aEngine.SCHEME_NAME
                            + " Secret Key Generatation, find "
                            + params.getClass().getName() + ", require "
                            + HIBBELLW16aSecretKeyGenerationParameter.class.getName() + " or "
                            + HIBBELLW16aDelegateGenerationParameter.class.getName());
        }
    }
}

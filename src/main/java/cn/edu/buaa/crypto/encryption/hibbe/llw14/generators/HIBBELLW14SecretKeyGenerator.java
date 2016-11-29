package cn.edu.buaa.crypto.encryption.hibbe.llw14.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEDelegateGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.HIBBELLW14Engine;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE secret key generator.
 */
public class HIBBELLW14SecretKeyGenerator implements PairingKeyParameterGenerator {
    private KeyGenerationParameters param;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.param = keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        if (param instanceof HIBBESecretKeyGenerationParameter) {
            HIBBESecretKeyGenerationParameter parameter = (HIBBESecretKeyGenerationParameter)param;

            HIBBELLW14PublicKeySerParameter publicKeyParameter = (HIBBELLW14PublicKeySerParameter)parameter.getPublicKeyParameter();
            HIBBELLW14MasterSecretKeySerParameter masterSecretKeyParameter = (HIBBELLW14MasterSecretKeySerParameter)parameter.getMasterSecretKeyParameter();

            if (parameter.getIds().length != publicKeyParameter.getMaxUser()) {
                throw new IllegalArgumentException("Invalid identity vector length");
            }
            Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
            Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, parameter.getIds(), PairingUtils.PairingGroupType.Zr);
            Element r = pairing.getZr().newRandomElement().getImmutable();
            Element a0_r = pairing.getZr().newRandomElement().getImmutable();
            Element a1_r = pairing.getZr().newRandomElement().getImmutable();
            Element[] bs_r = new Element[publicKeyParameter.getMaxUser()];

            Element a1 = publicKeyParameter.getG().powZn(r).mul(publicKeyParameter.getX3().powZn(a1_r)).getImmutable();
            Element a0 = publicKeyParameter.getH().getImmutable();
            Element[] bs = new Element[publicKeyParameter.getMaxUser()];

            for (int i=0; i<publicKeyParameter.getMaxUser(); i++){
                if (parameter.getIdAt(i) != null) {
                    //Compute a0
                    a0 = a0.mul(publicKeyParameter.getUsAt(i).powZn(elementIds[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    //Set h[i] to be h_i^r
                    bs_r[i] = pairing.getZr().newRandomElement().getImmutable();
                    bs[i] = publicKeyParameter.getUsAt(i).powZn(r).mul(publicKeyParameter.getX3().powZn(bs_r[i])).getImmutable();
                }
            }
            //raise a0 to the power of r and then multiple it by gAlpha
            a0 = a0.powZn(r).mul(masterSecretKeyParameter.getGAlpha()).mul(publicKeyParameter.getX3().powZn(a0_r)).getImmutable();

            return new HIBBELLW14SecretKeySerParameter(publicKeyParameter.getParameters(),
                    parameter.getIds(), elementIds, a0, a1, bs);
        } else if (param instanceof HIBBEDelegateGenerationParameter)  {
            HIBBEDelegateGenerationParameter parameter = (HIBBEDelegateGenerationParameter)param;

            HIBBELLW14PublicKeySerParameter publicKeyParameter = (HIBBELLW14PublicKeySerParameter)parameter.getPublicKeyParameter();
            HIBBELLW14SecretKeySerParameter secretKeyParameter = (HIBBELLW14SecretKeySerParameter)parameter.getSecretKeyParameter();
            if (secretKeyParameter.getIds().length != publicKeyParameter.getMaxUser()
                    || secretKeyParameter.getIds()[parameter.getIndex()] != null) {
                throw new IllegalArgumentException("Invalid identity vector length");
            }

            Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
            String[] ids = new String[publicKeyParameter.getMaxUser()];
            Element[] elementIds = new Element[publicKeyParameter.getMaxUser()];
            Element elementDelegateId = PairingUtils.MapStringToGroup(pairing, parameter.getDelegateId(), PairingUtils.PairingGroupType.Zr).getImmutable();

            Element a0_r = pairing.getZr().newRandomElement().getImmutable();
            Element a1_r = pairing.getZr().newRandomElement().getImmutable();
            Element[] bs_r = new Element[publicKeyParameter.getMaxUser()];
            Element t = pairing.getZr().newRandomElement().getImmutable();
            Element a0 = publicKeyParameter.getH().getImmutable();
            Element a1 = publicKeyParameter.getG().powZn(t).getImmutable();
            Element[] bs = new Element[publicKeyParameter.getMaxUser()];

            for (int i=0; i<publicKeyParameter.getMaxUser(); i++) {
                if (secretKeyParameter.getIdAt(i) != null) {
                    ids[i] = secretKeyParameter.getIdAt(i);
                    elementIds[i] = secretKeyParameter.getElementIdAt(i);
                    //Compute a0
                    a0 = a0.mul(publicKeyParameter.getUsAt(i).powZn(elementIds[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else if (i == parameter.getIndex()) {
                    ids[i] = parameter.getDelegateId();
                    elementIds[i] = elementDelegateId;
                    //Compute a0
                    a0 = a0.mul(publicKeyParameter.getUsAt(i).powZn(elementIds[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    bs_r[i] = pairing.getZr().newRandomElement().getImmutable();
                    bs[i] = secretKeyParameter.getBsAt(i)
                            .mul(publicKeyParameter.getUsAt(i).powZn(t)).mul(publicKeyParameter.getX3().powZn(bs_r[i])).getImmutable();
                }
            }
            //Compute the rest of a0
            a0 = a0.powZn(t).mul(secretKeyParameter.getA0())
                    .mul(secretKeyParameter.getBsAt(parameter.getIndex()).powZn(elementIds[parameter.getIndex()]))
                    .mul(publicKeyParameter.getX3().powZn(a0_r)).getImmutable();
            //Compute the result of a1
            a1 = a1.mul(secretKeyParameter.getA1()).mul(publicKeyParameter.getX3().powZn(a1_r)).getImmutable();

            return new HIBBELLW14SecretKeySerParameter(publicKeyParameter.getParameters(),
                    ids, elementIds, a0, a1, bs);
        } else {
            throw new IllegalArgumentException
                    ("Invalid KeyGenerationParameters for " + HIBBELLW14Engine.SCHEME_NAME
                            + " Secret Key Generatation, find "
                            + param.getClass().getName() + ", require "
                            + HIBBESecretKeyGenerationParameter.class.getName() + " or "
                            + HIBBEDelegateGenerationParameter.class.getName());
        }
    }
}

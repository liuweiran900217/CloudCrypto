package cn.edu.buaa.crypto.encryption.hibbe.llw17.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEDelegateGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.HIBBELLW17Engine;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE secret key generator.
 */
public class HIBBELLW17SecretKeyGenerator implements PairingKeyParameterGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        if (params instanceof HIBBESecretKeyGenerationParameter) {
            HIBBESecretKeyGenerationParameter parameters = (HIBBESecretKeyGenerationParameter)params;

            HIBBELLW17PublicKeySerParameter publicKeyParameters = (HIBBELLW17PublicKeySerParameter)parameters.getPublicKeyParameter();
            HIBBELLW17MasterSecretKeySerParameter masterSecretKeyParameters = (HIBBELLW17MasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();
            if (parameters.getIds().length != publicKeyParameters.getMaxUser()) {
                throw new IllegalArgumentException("Invalid identity vector length");
            }

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, parameters.getIds(), PairingUtils.PairingGroupType.Zr);
            Element r = pairing.getZr().newRandomElement().getImmutable();
            Element a0_r = pairing.getZr().newRandomElement().getImmutable();
            Element a1_r = pairing.getZr().newRandomElement().getImmutable();
            Element[] bs_r = new Element[publicKeyParameters.getMaxUser()];

            Element a1 = publicKeyParameters.getG().powZn(r).mul(publicKeyParameters.getX3().powZn(a1_r)).getImmutable();
            Element a0 = publicKeyParameters.getH().getImmutable();
            Element[] bs = new Element[publicKeyParameters.getMaxUser()];

            for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
                if (parameters.getIdAt(i) != null) {
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    //Set h[i] to be h_i^r
                    bs_r[i] = pairing.getZr().newRandomElement().getImmutable();
                    bs[i] = publicKeyParameters.getUsAt(i).powZn(r).mul(publicKeyParameters.getX3().powZn(bs_r[i])).getImmutable();
                }
            }
            Element bv_r = pairing.getZr().newRandomElement().getImmutable();
            Element bv = publicKeyParameters.getUv().powZn(r).mul(publicKeyParameters.getX3().powZn(bv_r)).getImmutable();
            //raise a0 to the power of r and then multiple it by gAlpha
            a0 = a0.powZn(r).mul(masterSecretKeyParameters.getGAlpha()).mul(publicKeyParameters.getX3().powZn(a0_r)).getImmutable();

            return new HIBBELLW17SecretKeySerParameter(publicKeyParameters.getParameters(),
                    parameters.getIds(), elementIds, a0, a1, bs, bv);
        } else if (params instanceof HIBBEDelegateGenerationParameter)  {
            HIBBEDelegateGenerationParameter parameters = (HIBBEDelegateGenerationParameter)params;

            HIBBELLW17PublicKeySerParameter publicKeyParameters = (HIBBELLW17PublicKeySerParameter)parameters.getPublicKeyParameter();
            HIBBELLW17SecretKeySerParameter secretKeyParameters = (HIBBELLW17SecretKeySerParameter)parameters.getSecretKeyParameter();
            if (secretKeyParameters.getIds().length != publicKeyParameters.getMaxUser()
                    || secretKeyParameters.getIds()[parameters.getIndex()] != null) {
                throw new IllegalArgumentException("Invalid identity vector length");
            }

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String[] ids = new String[publicKeyParameters.getMaxUser()];
            Element[] elementIds = new Element[publicKeyParameters.getMaxUser()];
            Element elementDelegateId = PairingUtils.MapStringToGroup(pairing, parameters.getDelegateId(), PairingUtils.PairingGroupType.Zr).getImmutable();

            Element a0_r = pairing.getZr().newRandomElement().getImmutable();
            Element a1_r = pairing.getZr().newRandomElement().getImmutable();
            Element[] bs_r = new Element[publicKeyParameters.getMaxUser()];
            Element t = pairing.getZr().newRandomElement().getImmutable();
            Element a0 = publicKeyParameters.getH().getImmutable();
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
                    bs_r[i] = pairing.getZr().newRandomElement().getImmutable();
                    bs[i] = secretKeyParameters.getBsAt(i)
                            .mul(publicKeyParameters.getUsAt(i).powZn(t)).mul(publicKeyParameters.getX3().powZn(bs_r[i])).getImmutable();
                }
            }
            Element bv_r = pairing.getZr().newRandomElement().getImmutable();
            Element bv = secretKeyParameters.getBv().mul(publicKeyParameters.getUv().powZn(t)).mul(publicKeyParameters.getX3().powZn(bv_r)).getImmutable();
            //Compute the rest of a0
            a0 = a0.powZn(t).mul(secretKeyParameters.getA0())
                    .mul(secretKeyParameters.getBsAt(parameters.getIndex()).powZn(elementIds[parameters.getIndex()]))
                    .mul(publicKeyParameters.getX3().powZn(a0_r)).getImmutable();
            //Compute the result of a1
            a1 = a1.mul(secretKeyParameters.getA1()).mul(publicKeyParameters.getX3().powZn(a1_r)).getImmutable();

            return new HIBBELLW17SecretKeySerParameter(publicKeyParameters.getParameters(),
                    ids, elementIds, a0, a1, bs, bv);
        } else {
            PairingUtils.NotVerifyCipherParameterInstance(HIBBELLW17Engine.SCHEME_NAME, params,
                    HIBBESecretKeyGenerationParameter.class.getName() + " or "
                    + HIBBEDelegateGenerationParameter.class.getName());
            return null;
        }
    }
}

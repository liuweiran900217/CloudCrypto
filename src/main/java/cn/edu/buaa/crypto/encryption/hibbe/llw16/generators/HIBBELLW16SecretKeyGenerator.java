package cn.edu.buaa.crypto.encryption.hibbe.llw16.generators;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.HIBBELLW16Engine;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16SecretKeyGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public CipherParameters generateKey() {
        if (params instanceof HIBBELLW16SecretKeyGenerationParameters) {
            HIBBELLW16SecretKeyGenerationParameters parameters = (HIBBELLW16SecretKeyGenerationParameters)params;

            HIBBELLW16PublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();
            HIBBELLW16MasterSecretKeyParameters masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            Element[] elementIds = Utils.MapToZr(pairing, parameters.getIds());
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

            return new HIBBELLW16SecretKeyParameters(publicKeyParameters.getParameters(),
                    parameters.getIds(), elementIds, a0, a1, bs);
        } else if (params instanceof HIBBELLW16DelegateGenerationParameters)  {
            HIBBELLW16DelegateGenerationParameters parameters = (HIBBELLW16DelegateGenerationParameters)params;

            HIBBELLW16PublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();
            HIBBELLW16SecretKeyParameters secretKeyParameters = parameters.getSecretKeyParameters();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String[] ids = new String[publicKeyParameters.getMaxUser()];
            Element[] elementIds = new Element[publicKeyParameters.getMaxUser()];
            Element elementDelegateId = Utils.MapToZr(pairing, parameters.getDelegateId()).getImmutable();

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

            return new HIBBELLW16SecretKeyParameters(publicKeyParameters.getParameters(),
                    ids, elementIds, a0, a1, bs);
        } else {
            throw new IllegalArgumentException
                    ("Invalid KeyGenerationParameters for " + HIBBELLW16Engine.SCHEME_NAME
                            + " Secret Key Generatation, find "
                            + params.getClass().getName() + ", require "
                            + HIBBELLW16SecretKeyGenerationParameters.class.getName() + " or "
                            + HIBBELLW16DelegateGenerationParameters.class.getName());
        }
    }
}

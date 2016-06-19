package cn.edu.buaa.crypto.application.llw15.generator;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import cn.edu.buaa.crypto.application.llw15.params.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/6/19.
 */
public class RBACLLW15AccessCredentialMGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public CipherParameters generateKey() {
        if (params instanceof RBACLLW15AccessCredentialMGenParameters) {
            RBACLLW15AccessCredentialMGenParameters parameters = (RBACLLW15AccessCredentialMGenParameters)params;

            RBACLLW15PublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();
            RBACLLW15MasterSecretKeyParameters masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            Element[] elementRoles = Utils.MapToZr(pairing, parameters.getRoles());
            Element elementTime = Utils.MapToZr(pairing, parameters.getTime());
            Element r = pairing.getZr().newRandomElement().getImmutable();

            Element a1 = publicKeyParameters.getG().powZn(r).getImmutable();
            Element a0 = publicKeyParameters.getG3().getImmutable();
            Element a2 = publicKeyParameters.getGh().powZn(r).getImmutable();
            Element bv = publicKeyParameters.getUv().powZn(r).getImmutable();
            Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];

            for (int i=0; i<publicKeyParameters.getMaxRoleNumber(); i++){
                if (parameters.getRoleAt(i) != null) {
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementRoles[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    //Set h[i] to be h_i^r
                    bs[i] = publicKeyParameters.getUsAt(i).powZn(r).getImmutable();
                }
            }
            //multiply u_0^t
            a0 = a0.mul(publicKeyParameters.getU0().powZn(elementTime)).getImmutable();
            //raise a0 to the power of r and then multiple it by gAlpha
            a0 = a0.powZn(r).mul(masterSecretKeyParameters.getG2Alpha()).getImmutable();

            return new RBACLLW15AccessCredentialMParameters(publicKeyParameters.getParameters(),
                    parameters.getRoles(), elementRoles, parameters.getTime(), elementTime, a0, a1, a2, bv, bs);
        } else if (params instanceof RBACLLW15AccessCredentialMDeleParameters)  {
            RBACLLW15AccessCredentialMDeleParameters parameters = (RBACLLW15AccessCredentialMDeleParameters)params;

            RBACLLW15PublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();
            RBACLLW15AccessCredentialMParameters secretKeyParameters = parameters.getSecretKeyParameters();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String[] roles = new String[publicKeyParameters.getMaxRoleNumber()];
            Element[] elementRoles = new Element[publicKeyParameters.getMaxRoleNumber()];
            Element elementDelegateRole = Utils.MapToZr(pairing, parameters.getDelegateRole()).getImmutable();

            Element t = pairing.getZr().newRandomElement().getImmutable();
            Element a0 = publicKeyParameters.getG3().getImmutable();
            Element a1 = publicKeyParameters.getG().powZn(t).getImmutable();
            Element a2 = secretKeyParameters.getA2().mul(publicKeyParameters.getGh().powZn(t)).getImmutable();
            Element bv = secretKeyParameters.getBv().mul(publicKeyParameters.getUv().powZn(t)).getImmutable();
            Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];

            for (int i=0; i<publicKeyParameters.getMaxRoleNumber(); i++) {
                if (secretKeyParameters.getRoleAt(i) != null) {
                    roles[i] = secretKeyParameters.getRoleAt(i);
                    elementRoles[i] = secretKeyParameters.getElementRoleAt(i);
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementRoles[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else if (i == parameters.getIndex()) {
                    roles[i] = parameters.getDelegateRole();
                    elementRoles[i] = elementDelegateRole.getImmutable();
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementRoles[i])).getImmutable();
                    //Set h[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    bs[i] = secretKeyParameters.getBsAt(i)
                            .mul(publicKeyParameters.getUsAt(i).powZn(t)).getImmutable();
                }
            }
            //Compute the rest of a0
            a0 = a0.mul(publicKeyParameters.getU0().powZn(secretKeyParameters.getElementTime()))
                    .powZn(t).mul(secretKeyParameters.getA0())
                    .mul(secretKeyParameters.getBsAt(parameters.getIndex()).powZn(elementRoles[parameters.getIndex()])).getImmutable();
            //Compute the result of a1
            a1 = a1.mul(secretKeyParameters.getA1()).getImmutable();

            return new RBACLLW15AccessCredentialMParameters(publicKeyParameters.getParameters(),
                    roles, elementRoles, secretKeyParameters.getTime(), secretKeyParameters.getElementTime(),
                    a0, a1, a2, bv, bs);
        } else {
            throw new IllegalArgumentException
                    ("Invalid KeyGenerationParameters for " + RBACLLW15Engine.SCHEME_NAME
                            + " Secret Key Generatation, find "
                            + params.getClass().getName() + ", require "
                            + RBACLLW15AccessCredentialMGenParameters.class.getName() + " or "
                            + RBACLLW15AccessCredentialMDeleParameters.class.getName());
        }
    }
}

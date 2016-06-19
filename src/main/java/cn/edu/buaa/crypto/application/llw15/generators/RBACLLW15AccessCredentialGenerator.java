package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import cn.edu.buaa.crypto.application.llw15.params.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/5/19.
 */
public class RBACLLW15AccessCredentialGenerator {
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
            String[] roles = parameters.getRoles();
            Element[] elementRoles = Utils.MapToZr(pairing, parameters.getRoles());
            Element elementTime = Utils.MapToZr(pairing, parameters.getTime());
            Element r = pairing.getZr().newRandomElement().getImmutable();

            Element a1 = publicKeyParameters.getG().powZn(r).getImmutable();
            Element a2 = publicKeyParameters.getGh().powZn(r).getImmutable();
            Element bv = publicKeyParameters.getUv().powZn(r).getImmutable();
            //multiply g3 and u_0^t to a0
            Element a0 = publicKeyParameters.getG3().getImmutable();
            a0 = a0.mul(publicKeyParameters.getU0().powZn(elementTime)).getImmutable();
            Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];

            for (int i=0; i<publicKeyParameters.getMaxRoleNumber(); i++){
                if (parameters.getRoleAt(i) != null) {
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementRoles[i])).getImmutable();
                    //Set b[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    //Set b[i] to be u_i^r
                    bs[i] = publicKeyParameters.getUsAt(i).powZn(r).getImmutable();
                }
            }
            //raise a0 to the power of r and then multiple it by gAlpha
            a0 = a0.powZn(r).mul(masterSecretKeyParameters.getG2Alpha()).getImmutable();

            return new RBACLLW15AccessCredentialMParameters(publicKeyParameters.getParameters(), roles, elementRoles,
                    parameters.getTime(), elementTime, a0, a1, a2, bv, bs);
        } else if (params instanceof RBACLLW15AccessCredentialMDeleParameters)  {
            RBACLLW15AccessCredentialMDeleParameters parameters = (RBACLLW15AccessCredentialMDeleParameters)params;

            RBACLLW15PublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();
            RBACLLW15AccessCredentialMParameters accessCredentialMParameters = parameters.getAccessCredentialMParameters();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String[] roles = new String[publicKeyParameters.getMaxRoleNumber()];
            Element[] elementRoles = new Element[publicKeyParameters.getMaxRoleNumber()];
            Element elementDelegateRole = Utils.MapToZr(pairing, parameters.getDelegateRole()).getImmutable();

            Element s = pairing.getZr().newRandomElement().getImmutable();
            Element a0 = publicKeyParameters.getG3().getImmutable();
            a0 = a0.mul(publicKeyParameters.getU0().powZn(accessCredentialMParameters.getElementTime())).getImmutable();
            Element a1 = publicKeyParameters.getG().powZn(s).getImmutable();
            Element a2 = publicKeyParameters.getGh().powZn(s).getImmutable();
            Element bv = publicKeyParameters.getUv().powZn(s).getImmutable();
            Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];

            for (int i=0; i<publicKeyParameters.getMaxRoleNumber(); i++) {
                if (accessCredentialMParameters.getRoleAt(i) != null) {
                    roles[i] = accessCredentialMParameters.getRoleAt(i);
                    elementRoles[i] = accessCredentialMParameters.getElementRoleAt(i);
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementRoles[i])).getImmutable();
                    //Set b[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else if (i == parameters.getIndex()) {
                    roles[i] = parameters.getDelegateRole();
                    elementRoles[i] = elementDelegateRole;
                    //Compute a0
                    a0 = a0.mul(publicKeyParameters.getUsAt(i).powZn(elementRoles[i])).getImmutable();
                    //Set b[i] to be one
                    bs[i] = pairing.getG1().newOneElement().getImmutable();
                } else {
                    bs[i] = accessCredentialMParameters.getBsAt(i)
                            .mul(publicKeyParameters.getUsAt(i).powZn(s)).getImmutable();
                }
            }
            //Compute the rest of a0
            a0 = a0.powZn(s).mul(accessCredentialMParameters.getA0())
                    .mul(accessCredentialMParameters.getBsAt(parameters.getIndex()).powZn(elementRoles[parameters.getIndex()])).getImmutable();
            //Compute the result of a1
            a1 = a1.mul(accessCredentialMParameters.getA1()).getImmutable();
            //Compute the result of a2
            a2 = a2.mul(accessCredentialMParameters.getA2()).getImmutable();
            //Compute the result of bv
            bv = bv.mul(accessCredentialMParameters.getBv()).getImmutable();

            return new RBACLLW15AccessCredentialMParameters(publicKeyParameters.getParameters(), roles, elementRoles,
                    accessCredentialMParameters.getTime(), accessCredentialMParameters.getElementTime(),
                    a0, a1, a2, bv, bs);
        } else if (params instanceof RBACLLW15AccessCredentialPGenParameters) {
            RBACLLW15AccessCredentialPGenParameters parameters = (RBACLLW15AccessCredentialPGenParameters)params;

            RBACLLW15PublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();
            RBACLLW15MasterSecretKeyParameters masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String id = parameters.getId();
            Element elementId = Utils.MapToZr(pairing, id);
            Element r = pairing.getZr().newRandomElement().getImmutable();

            Element a1Prime = publicKeyParameters.getG().powZn(r).getImmutable();
            Element a0Prime = publicKeyParameters.getG3().getImmutable();
            a0Prime = a0Prime.mul(publicKeyParameters.getGh().powZn(elementId)).getImmutable();
            Element b0Prime = publicKeyParameters.getU0().powZn(r).getImmutable();
            Element bvPrime = publicKeyParameters.getUv().powZn(r).getImmutable();
            Element[] bsPrime = new Element[publicKeyParameters.getMaxRoleNumber()];
            for (int i=0; i<publicKeyParameters.getMaxRoleNumber(); i++){
                //Set bsPrime[i] to be u_i^r
                bsPrime[i] = publicKeyParameters.getUsAt(i).powZn(r).getImmutable();
            }
            //raise a0 to the power of r and then multiple it by gAlpha
            a0Prime = a0Prime.powZn(r).mul(masterSecretKeyParameters.getG2Alpha()).getImmutable();

            return new RBACLLW15AccessCredentialPParameters(publicKeyParameters.getParameters(), id, elementId,
                    a0Prime, a1Prime, b0Prime, bvPrime, bsPrime);
        } else {
            throw new IllegalArgumentException
                    ("Invalid KeyGenerationParameters for " + RBACLLW15Engine.SCHEME_NAME
                            + " Secret Key Generatation, find "
                            + params.getClass().getName() + ", require "
                            + RBACLLW15AccessCredentialMGenParameters.class.getName() + " or "
                            + RBACLLW15AccessCredentialMDeleParameters.class.getName() + " or "
                            + RBACLLW15AccessCredentialPGenParameters.class.getName());
        }
    }
}
package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.genparams.RBACLLW15AccessCredentialMDeleParameter;
import cn.edu.buaa.crypto.application.llw15.genparams.RBACLLW15AccessCredentialMGenParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import cn.edu.buaa.crypto.application.llw15.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/6/19.
 *
 * Liu-Liu-Wu role-based access control medial staff access credential generator.
 */
public class RBACLLW15AccessCredentialMGenerator implements PairingKeyParameterGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        if (params instanceof RBACLLW15AccessCredentialMGenParameter) {
            RBACLLW15AccessCredentialMGenParameter parameters = (RBACLLW15AccessCredentialMGenParameter)params;

            RBACLLW15PublicKeySerParameter publicKeyParameters = (RBACLLW15PublicKeySerParameter)parameters.getPublicKeyParameter();
            RBACLLW15MasterSecretKeySerParameter masterSecretKeyParameters = (RBACLLW15MasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            Element[] elementRoles = PairingUtils.MapStringArrayToGroup(pairing, parameters.getRoles(), PairingUtils.PairingGroupType.Zr);
            Element elementTime = PairingUtils.MapStringToGroup(pairing, parameters.getTime(), PairingUtils.PairingGroupType.Zr);
            if (!parameters.isIntermediateGeneration()) {
                //generate medical staff access credential without using intermediate parameters
                Element r = pairing.getZr().newRandomElement().getImmutable();

                Element a1 = publicKeyParameters.getG().powZn(r).getImmutable();
                Element a0 = publicKeyParameters.getG3().getImmutable();
                Element a2 = publicKeyParameters.getGh().powZn(r).getImmutable();
                Element bv = publicKeyParameters.getUv().powZn(r).getImmutable();
                Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];

                for (int i = 0; i < publicKeyParameters.getMaxRoleNumber(); i++){
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

                return new RBACLLW15AccessCredentialMSerParameter(publicKeyParameters.getParameters(),
                        parameters.getRoles(), elementRoles, parameters.getTime(), elementTime, a0, a1, a2, bv, bs);
            } else {
                //generate medical staff access credential using intermediate parameters
                RBACLLW15IntermediateSerParameter intermediateParameters = parameters.getIntermediateParameters();

                Element a1 = intermediateParameters.get_G_r().getImmutable();
                Element a0 = masterSecretKeyParameters.getG2Alpha()
                        .mul(intermediateParameters.get_G_3_r()).getImmutable();
                Element a2 = intermediateParameters.get_G_h_r().getImmutable();
                Element bv = intermediateParameters.get_U_v_r().getImmutable();
                Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];

                for (int i = 0; i < bs.length; i++) {
                    if (parameters.getRoleAt(i) != null) {
                        a0 = a0.mul(intermediateParameters.get_U_s_r_at(i).powZn(elementRoles[i])).getImmutable();
                        bs[i] = pairing.getG1().newOneElement().getImmutable();
                    } else {
                        bs[i] = intermediateParameters.get_U_s_r_at(i).getImmutable();
                    }
                }
                a0 = a0.mul(intermediateParameters.get_U_0_r().powZn(elementTime)).getImmutable();

                return new RBACLLW15AccessCredentialMSerParameter(publicKeyParameters.getParameters(),
                        parameters.getRoles(), elementRoles, parameters.getTime(), elementTime, a0, a1, a2, bv, bs);
            }

        } else if (params instanceof RBACLLW15AccessCredentialMDeleParameter)  {
            RBACLLW15AccessCredentialMDeleParameter parameters = (RBACLLW15AccessCredentialMDeleParameter)params;

            RBACLLW15PublicKeySerParameter publicKeyParameters = (RBACLLW15PublicKeySerParameter)parameters.getPublicKeyParameter();
            RBACLLW15AccessCredentialMSerParameter secretKeyParameters = (RBACLLW15AccessCredentialMSerParameter)parameters.getSecretKeyParameter();

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            String[] roles = new String[publicKeyParameters.getMaxRoleNumber()];
            Element[] elementRoles = new Element[publicKeyParameters.getMaxRoleNumber()];
            Element elementDelegateRole = PairingUtils.MapStringToGroup(pairing, parameters.getDelegateRole(), PairingUtils.PairingGroupType.Zr).getImmutable();
            if (!parameters.isIntermediateGeneration()) {
                //generate medical staff access credential without using intermediate parameters
                Element t = pairing.getZr().newRandomElement().getImmutable();
                Element a0 = publicKeyParameters.getG3().getImmutable();
                Element a1 = secretKeyParameters.getA1().mul(publicKeyParameters.getG().powZn(t)).getImmutable();
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

                return new RBACLLW15AccessCredentialMSerParameter(publicKeyParameters.getParameters(),
                        roles, elementRoles, secretKeyParameters.getTime(), secretKeyParameters.getElementTime(),
                        a0, a1, a2, bv, bs);
            } else {
                //generate medical staff access credential using intermediate parameters
                RBACLLW15IntermediateSerParameter intermediateParameters = parameters.getIntermediateParameters();
                Element a0 = intermediateParameters.get_G_3_r().getImmutable();
                Element a1 = secretKeyParameters.getA1().mul(intermediateParameters.get_G_r()).getImmutable();
                Element a2 = secretKeyParameters.getA2().mul(intermediateParameters.get_G_h_r()).getImmutable();
                Element bv = secretKeyParameters.getBv().mul(intermediateParameters.get_U_v_r()).getImmutable();
                Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];
                for (int i = 0; i < bs.length; i++) {
                    if (secretKeyParameters.getRoleAt(i) != null) {
                        roles[i] = secretKeyParameters.getRoleAt(i);
                        elementRoles[i] = secretKeyParameters.getElementRoleAt(i);
                        //Compute a0
                        a0 = a0.mul(intermediateParameters.get_U_s_r_at(i).powZn(elementRoles[i])).getImmutable();
                        //Set h[i] to be one
                        bs[i] = pairing.getG1().newOneElement().getImmutable();
                    } else if (i == parameters.getIndex()) {
                        roles[i] = parameters.getDelegateRole();
                        elementRoles[i] = elementDelegateRole.getImmutable();
                        //Compute a0
                        a0 = a0.mul(intermediateParameters.get_U_s_r_at(i).powZn(elementRoles[i])).getImmutable();
                        //Set h[i] to be one
                        bs[i] = pairing.getG1().newOneElement().getImmutable();
                    } else {
                        bs[i] = secretKeyParameters.getBsAt(i)
                                .mul(intermediateParameters.get_U_s_r_at(i)).getImmutable();
                    }
                }
                //Compute the rest of a0
                a0 = a0.mul(intermediateParameters.get_U_0_r().powZn(secretKeyParameters.getElementTime()))
                        .mul(secretKeyParameters.getA0())
                        .mul(secretKeyParameters.getBsAt(parameters.getIndex()).powZn(elementRoles[parameters.getIndex()])).getImmutable();

                return new RBACLLW15AccessCredentialMSerParameter(publicKeyParameters.getParameters(),
                        roles, elementRoles, secretKeyParameters.getTime(), secretKeyParameters.getElementTime(),
                        a0, a1, a2, bv, bs);
            }
        } else {
            PairingUtils.NotVerifyCipherParameterInstance(RBACLLW15Engine.SCHEME_NAME, params,
                    RBACLLW15AccessCredentialMGenParameter.class.getName() + " or "
                    + RBACLLW15AccessCredentialMDeleParameter.class.getName());
            return null;
        }
    }
}

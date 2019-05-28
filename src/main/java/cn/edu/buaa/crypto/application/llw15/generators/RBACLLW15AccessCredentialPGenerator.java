package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyParameterGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.genparams.RBACLLW15AccessCredentialPGenParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15AccessCredentialPSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 16/6/19.
 *
 * Liu-Liu-Wu role-based access control patient access credential generator.
 */
public class RBACLLW15AccessCredentialPGenerator implements PairingKeyParameterGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public PairingKeySerParameter generateKey() {
        RBACLLW15AccessCredentialPGenParameter parameters = (RBACLLW15AccessCredentialPGenParameter) params;
        RBACLLW15PublicKeySerParameter publicKeyParameters = (RBACLLW15PublicKeySerParameter)parameters.getPublicKeyParameter();
        RBACLLW15MasterSecretKeySerParameter masterSecretKeyParameters = (RBACLLW15MasterSecretKeySerParameter)parameters.getMasterSecretKeyParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementId = PairingUtils.MapStringToGroup(pairing, parameters.getId(), PairingUtils.PairingGroupType.Zr);
        if (!parameters.isIntermediateGeneration()) {
            //generate patient access credential without using intermediate
            Element r = pairing.getZr().newRandomElement().getImmutable();

            Element a1 = publicKeyParameters.getG().powZn(r).getImmutable();
            Element a0 = publicKeyParameters.getG3().getImmutable();
            Element b0 = publicKeyParameters.getU0().powZn(r).getImmutable();
            Element bv = publicKeyParameters.getUv().powZn(r).getImmutable();
            Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];

            a0 = a0.mul(publicKeyParameters.getGh().powZn(elementId)).getImmutable();
            a0 = a0.powZn(r).mul(masterSecretKeyParameters.getG2Alpha()).getImmutable();
            for (int i = 0; i < publicKeyParameters.getMaxRoleNumber(); i++) {
                //Set h[i] to be h_i^r
                bs[i] = publicKeyParameters.getUsAt(i).powZn(r).getImmutable();
            }
            return new RBACLLW15AccessCredentialPSerParameter(publicKeyParameters.getParameters(),
                    parameters.getId(), elementId, a0, a1, b0, bv, bs);
        } else {
            //generate patient access control using intermediate
            RBACLLW15IntermediateSerParameter intermediateParameters = parameters.getIntermediateParameters();
            Element a0 = intermediateParameters.get_G_h_r().powZn(elementId)
                    .mul(intermediateParameters.get_G_3_r())
                    .mul(masterSecretKeyParameters.getG2Alpha()).getImmutable();
            Element a1 = intermediateParameters.get_G_r().getImmutable();
            Element b0 = intermediateParameters.get_U_0_r().getImmutable();
            Element bv = intermediateParameters.get_U_v_r().getImmutable();
            Element[] bs = new Element[publicKeyParameters.getMaxRoleNumber()];
            for (int i = 0; i < bs.length; i++) {
                bs[i] = intermediateParameters.get_U_s_r_at(i).getImmutable();
            }
            return new RBACLLW15AccessCredentialPSerParameter(publicKeyParameters.getParameters(),
                    parameters.getId(), elementId, a0, a1, b0, bv, bs);
        }
    }
}

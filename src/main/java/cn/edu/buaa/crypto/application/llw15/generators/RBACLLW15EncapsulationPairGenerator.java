package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.application.llw15.genparams.RBACLLW15EncapsulationGenParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15EncapsulationSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/6/19.
 *
 * Liu-Liu-Wu role-based access control key encapsulation pair generator.
 */
public class RBACLLW15EncapsulationPairGenerator implements PairingEncapsulationPairGenerator {
    private RBACLLW15EncapsulationGenParameter params;

    public void init(CipherParameters params) {
        this.params = (RBACLLW15EncapsulationGenParameter)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        RBACLLW15PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] roles = this.params.getRoles();
        Element[] elementRoles = PairingUtils.MapToZr(pairing, roles);
        String time = this.params.getTime();
        Element elementTime = PairingUtils.MapToZr(pairing, time);
        String identity = this.params.getId();
        Element elementId = PairingUtils.MapToZr(pairing, identity);

        if (!params.isIntermediateGeneration()) {
            //encapsulate key without using intermediate parameters
            Element beta = pairing.getZr().newRandomElement().getImmutable();
            Element sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2()).powZn(beta).getImmutable();
            byte[] byteArraySessionKey = sessionKey.toBytes();

            Element C0 = publicKeyParameters.getG().powZn(beta).getImmutable();
            Element w = PairingUtils.MapToZr(pairing, C0.toBytes());
            Element C1 = publicKeyParameters.getG3().getImmutable();
            for (int i = 0; i < publicKeyParameters.getMaxRoleNumber(); i++) {
                if (roles[i] != null) {
                    C1 = C1.mul(publicKeyParameters.getUsAt(i).powZn(elementRoles[i])).getImmutable();
                }
            }
            C1 = C1.mul(publicKeyParameters.getU0().powZn(elementTime)).getImmutable();
            C1 = C1.mul(publicKeyParameters.getGh().powZn(elementId)).getImmutable();
            C1 = C1.mul(publicKeyParameters.getUv().powZn(w)).getImmutable();
            C1 = C1.powZn(beta).getImmutable();
            return new PairingKeyEncapsulationSerPair(
                    byteArraySessionKey,
                    new RBACLLW15EncapsulationSerParameter(publicKeyParameters.getParameters(), C0, C1));
        } else {
            //encapsulate key using intermediate parameters
            RBACLLW15IntermediateSerParameter intermediateParameters = params.getIntermediateParameters();
            Element sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2())
                    .powZn(intermediateParameters.get_r()).getImmutable();
            byte[] byteArraySessionKey = sessionKey.toBytes();

            Element C0 = intermediateParameters.get_G_r().getImmutable();
            Element w = PairingUtils.MapToZr(pairing, C0.toBytes());
            Element C1 = intermediateParameters.get_G_3_r().getImmutable();
            for (int i = 0; i < publicKeyParameters.getMaxRoleNumber(); i++) {
                if (roles[i] != null) {
                    C1 = C1.mul(intermediateParameters.get_U_s_r_at(i).powZn(elementRoles[i])).getImmutable();
                }
            }
            C1 = C1.mul(intermediateParameters.get_U_0_r().powZn(elementTime)).getImmutable();
            C1 = C1.mul(intermediateParameters.get_G_h_r().powZn(elementId)).getImmutable();
            C1 = C1.mul(intermediateParameters.get_U_v_r().powZn(w)).getImmutable();
            return new PairingKeyEncapsulationSerPair(
                    byteArraySessionKey,
                    new RBACLLW15EncapsulationSerParameter(publicKeyParameters.getParameters(), C0, C1));
        }
    }
}
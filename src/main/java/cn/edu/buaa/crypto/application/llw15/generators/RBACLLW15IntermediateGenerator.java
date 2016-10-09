package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15IntermediateGenParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15IntermediateParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/10/8.
 *
 * Liu-Liu-Wu role-based access control intermediate generator.
 */
public class RBACLLW15IntermediateGenerator {
    private RBACLLW15IntermediateGenParameters params;

    public void init(RBACLLW15IntermediateGenParameters intermediateGenParameters) {
        this.params = intermediateGenParameters;
    }

    public RBACLLW15IntermediateParameters generateIntermadiateParameters() {
        RBACLLW15PublicKeyParameters publicKeyParameters = params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element r = pairing.getZr().newRandomElement().getImmutable();

        Element g_3_r = publicKeyParameters.getG3().powZn(r).getImmutable();
        Element g_h_r = publicKeyParameters.getGh().powZn(r).getImmutable();
        Element g_r = publicKeyParameters.getG().powZn(r).getImmutable();
        Element u_0_r = publicKeyParameters.getU0().powZn(r).getImmutable();
        Element u_v_r = publicKeyParameters.getUv().powZn(r).getImmutable();
        Element[] u_s_r = new Element[publicKeyParameters.getMaxRoleNumber()];
        for (int i = 0; i < u_s_r.length; i++) {
            u_s_r[i] = publicKeyParameters.getUsAt(i).powZn(r).getImmutable();
        }

        return new RBACLLW15IntermediateParameters(r, g_3_r, g_h_r, g_r, u_0_r, u_v_r, u_s_r);
    }
}

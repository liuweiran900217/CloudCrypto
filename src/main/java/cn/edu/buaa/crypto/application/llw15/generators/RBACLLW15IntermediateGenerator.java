package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.application.llw15.genparams.RBACLLW15IntermediateGenParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15IntermediateSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
 * Created by Weiran Liu on 2016/10/8.
 *
 * Liu-Liu-Wu role-based access control intermediate generator.
 */
public class RBACLLW15IntermediateGenerator {
    private RBACLLW15IntermediateGenParameter params;

    public void init(RBACLLW15IntermediateGenParameter intermediateGenParameters) {
        this.params = intermediateGenParameters;
    }

    public RBACLLW15IntermediateSerParameter generateIntermadiateParameters() {
        RBACLLW15PublicKeySerParameter publicKeyParameters = params.getPublicKeyParameters();
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

        return new RBACLLW15IntermediateSerParameter(publicKeyParameters.getParameters(), r, g_3_r, g_h_r, g_r, u_0_r, u_v_r, u_s_r);
    }
}

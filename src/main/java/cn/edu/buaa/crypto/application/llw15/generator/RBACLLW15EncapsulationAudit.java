package cn.edu.buaa.crypto.application.llw15.generator;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15EncapsulationAuditParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15EncapsulationParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15PublicKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/6/19.
 */
public class RBACLLW15EncapsulationAudit {
    private RBACLLW15EncapsulationAuditParameters params;

    public void init(CipherParameters params) {
        this.params = (RBACLLW15EncapsulationAuditParameters)params;
    }

    public boolean audit() {
        RBACLLW15PublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        RBACLLW15EncapsulationParameters encapsulationParameters = this.params.getCiphertextParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] roles = this.params.getRoles();
        Element[] elementRoles = Utils.MapToZr(pairing, roles);
        String time = this.params.getTime();
        Element elementTime = Utils.MapToZr(pairing, time);
        String identity = this.params.getId();
        Element elementId = Utils.MapToZr(pairing, identity);

        Element temp00 = publicKeyParameters.getG();
        Element temp01 = encapsulationParameters.getC1();
        Element temp10 = encapsulationParameters.getC0();
        Element temp11  = publicKeyParameters.getG3().mul(publicKeyParameters.getU0().powZn(elementTime))
                .mul(publicKeyParameters.getGh().powZn(elementId))
                .mul(publicKeyParameters.getUv().powZn(Utils.MapToZr(pairing, encapsulationParameters.getC0().toBytes()))).getImmutable();
        for (int i=0; i<roles.length; i++) {
            if (roles[i] != null) {
                temp11 = temp11.mul(publicKeyParameters.getUsAt(i).powZn(elementRoles[i])).getImmutable();
            }
        }
        Element temp0 = pairing.pairing(temp00, temp01).getImmutable();
        Element temp1 = pairing.pairing(temp10, temp11).getImmutable();
        return temp0.equals(temp1);
    }
}

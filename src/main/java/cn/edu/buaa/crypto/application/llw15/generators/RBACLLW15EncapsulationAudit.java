package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.application.llw15.genparams.RBACLLW15EncapsulationAuditParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15EncapsulationSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/6/19.
 *
 * Liu-Liu-Wu role-based access control encapsulation audit.
 */
public class RBACLLW15EncapsulationAudit {
    private RBACLLW15EncapsulationAuditParameter params;

    public void init(CipherParameters params) {
        this.params = (RBACLLW15EncapsulationAuditParameter)params;
    }

    public boolean audit() {
        RBACLLW15PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        RBACLLW15EncapsulationSerParameter encapsulationParameters = this.params.getCiphertextParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] roles = this.params.getRoles();
        Element[] elementRoles = PairingUtils.MapStringArrayToGroup(pairing, roles, PairingUtils.PairingGroupType.Zr);
        String time = this.params.getTime();
        Element elementTime = PairingUtils.MapStringToGroup(pairing, time, PairingUtils.PairingGroupType.Zr);
        String identity = this.params.getId();
        Element elementId = PairingUtils.MapStringToGroup(pairing, identity, PairingUtils.PairingGroupType.Zr);

        Element temp00 = publicKeyParameters.getG();
        Element temp01 = encapsulationParameters.getC1();
        Element temp10 = encapsulationParameters.getC0();
        Element temp11  = publicKeyParameters.getG3().mul(publicKeyParameters.getU0().powZn(elementTime))
                .mul(publicKeyParameters.getGh().powZn(elementId))
                .mul(publicKeyParameters.getUv().powZn(
                        PairingUtils.MapByteArrayToGroup(
                                pairing, encapsulationParameters.getC0().toBytes(), PairingUtils.PairingGroupType.Zr))).getImmutable();
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

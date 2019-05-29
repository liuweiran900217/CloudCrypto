package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.application.llw15.genparams.RBACLLW15DecapsulationMParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15AccessCredentialMSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15EncapsulationSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/6/19.
 *
 * Liu-Liu-Wu role-based access control medical staff key decapsulation generator.
 */
public class RBACLLW15DecapsulationMGenerator implements PairingDecapsulationGenerator {
    private RBACLLW15DecapsulationMParameter params;

    public void init(CipherParameters params) {
        this.params = (RBACLLW15DecapsulationMParameter)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        RBACLLW15PublicKeySerParameter publicKeyParameters = (RBACLLW15PublicKeySerParameter) this.params.getPublicKeyParameter();
        RBACLLW15AccessCredentialMSerParameter secretKeyParameters = (RBACLLW15AccessCredentialMSerParameter)this.params.getSecretKeyParameter();
        RBACLLW15EncapsulationSerParameter ciphertextParameters = (RBACLLW15EncapsulationSerParameter)this.params.getCiphertextParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementRolesCT = PairingUtils.MapStringArrayToGroup(pairing, this.params.getRoles(), PairingUtils.PairingGroupType.Zr);
        Element elementIdCT = PairingUtils.MapStringToGroup(pairing, this.params.getId(), PairingUtils.PairingGroupType.Zr);

        //Check time
        if (!secretKeyParameters.getTime().equals(this.params.getTime())) {
            throw new InvalidCipherTextException("Medical Stuff time does not match Encapsulation time");
        }
        //Check roles
        for (int i=0; i<publicKeyParameters.getMaxRoleNumber(); i++){
            if (secretKeyParameters.getRoleAt(i) != null &&
                    !secretKeyParameters.getElementRoleAt(i).equals(elementRolesCT[i])){
                throw new InvalidCipherTextException("Secret Key role vector does not match Ciphertext role vector set, " +
                        "index = " + i);
            }
        }

        Element a0 = secretKeyParameters.getA0().getImmutable();
        Element C0 = ciphertextParameters.getC0().getImmutable();
        Element C1 = ciphertextParameters.getC1().getImmutable();
        Element a1 = secretKeyParameters.getA1().getImmutable();

        for (int i=0; i<publicKeyParameters.getMaxRoleNumber(); i++){
            if (secretKeyParameters.getRoleAt(i) == null && params.getRoleAt(i) != null) {
                a0 = a0.mul(secretKeyParameters.getBsAt(i).powZn(elementRolesCT[i])).getImmutable();
            }
        }
        a0 = a0.mul(secretKeyParameters.getA2().powZn(elementIdCT)).getImmutable();
        a0 = a0.mul(secretKeyParameters.getBv().powZn(PairingUtils.MapByteArrayToGroup(pairing, C0.toBytes(), PairingUtils.PairingGroupType.Zr))).getImmutable();

        Element temp0 = pairing.pairing(C0, a0).getImmutable();
        Element temp1 = pairing.pairing(a1, C1).getImmutable();
        return temp0.div(temp1).getImmutable().toBytes();
    }
}
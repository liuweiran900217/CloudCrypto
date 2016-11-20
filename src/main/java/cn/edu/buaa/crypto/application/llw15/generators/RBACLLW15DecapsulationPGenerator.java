package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15AccessCredentialPSerParameter;
import cn.edu.buaa.crypto.application.llw15.genparams.RBACLLW15DecapsulationPParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15EncapsulationSerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/6/19.
 *
 * Liu-Liu-Wu role-based access control patient's key deacapsulation generator.
 */
public class RBACLLW15DecapsulationPGenerator implements PairingDecapsulationGenerator {
    private RBACLLW15DecapsulationPParameter params;

    public void init(CipherParameters params) {
        this.params = (RBACLLW15DecapsulationPParameter)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        RBACLLW15PublicKeySerParameter publicKeyParameters = (RBACLLW15PublicKeySerParameter)this.params.getPublicKeyParameter();
        RBACLLW15AccessCredentialPSerParameter secretKeyParameters = (RBACLLW15AccessCredentialPSerParameter)this.params.getSecretKeyParameter();
        RBACLLW15EncapsulationSerParameter ciphertextParameters = (RBACLLW15EncapsulationSerParameter)this.params.getCiphertextParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementRolesCT = PairingUtils.MapStringArrayToGroup(pairing, this.params.getRoles(), PairingUtils.PairingGroupType.Zr);
        Element elementTimeCT = PairingUtils.MapStringToGroup(pairing, this.params.getTime(), PairingUtils.PairingGroupType.Zr);

        //Check identity
        if (!secretKeyParameters.getId().equals(this.params.getId())) {
            throw new InvalidCipherTextException("Patient identity does not match Encapsulation identity");
        }

        Element a0 = secretKeyParameters.getA0Prime().getImmutable();
        Element C0 = ciphertextParameters.getC0().getImmutable();
        Element C1 = ciphertextParameters.getC1().getImmutable();
        Element a1 = secretKeyParameters.getA1Prime().getImmutable();

        for (int i=0; i<publicKeyParameters.getMaxRoleNumber(); i++){
            if (params.getRolesAt(i) != null) {
                a0 = a0.mul(secretKeyParameters.getBsPrimeAt(i).powZn(elementRolesCT[i])).getImmutable();
            }
        }
        a0 = a0.mul(secretKeyParameters.getB0Prime().powZn(elementTimeCT))
                .mul(secretKeyParameters.getBvPrime().powZn(PairingUtils.MapByteArrayToGroup(pairing, C0.toBytes(), PairingUtils.PairingGroupType.Zr))).getImmutable();
        Element temp0 = pairing.pairing(C0, a0).getImmutable();
        Element temp1 = pairing.pairing(a1, C1).getImmutable();
        return temp0.div(temp1).getImmutable().toBytes();
    }
}
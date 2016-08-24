package cn.edu.buaa.crypto.application.llw15.generators;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15AccessCredentialPParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15DecapsulationPParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15EncapsulationParameters;
import cn.edu.buaa.crypto.application.llw15.params.RBACLLW15PublicKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generators.PairingKeyDecapsulationGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/6/19.
 */
public class RBACLLW15DecapsulationPGenerator implements PairingKeyDecapsulationGenerator {
    private RBACLLW15DecapsulationPParameters params;

    public void init(CipherParameters params) {
        this.params = (RBACLLW15DecapsulationPParameters)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        RBACLLW15PublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        RBACLLW15AccessCredentialPParameters secretKeyParameters = this.params.getSecretKeyParameters();
        RBACLLW15EncapsulationParameters ciphertextParameters = this.params.getCiphertextParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementRolesCT = PairingUtils.MapToZr(pairing, this.params.getRoles());
        Element elementTimeCT = PairingUtils.MapToZr(pairing, this.params.getTime());

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
                .mul(secretKeyParameters.getBvPrime().powZn(PairingUtils.MapToZr(pairing, C0.toBytes()))).getImmutable();
        Element temp0 = pairing.pairing(C0, a0).getImmutable();
        Element temp1 = pairing.pairing(a1, C1).getImmutable();
        Element sessionKey = temp0.div(temp1).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();
        return Arrays.copyOf(byteArraySessionKey, byteArraySessionKey.length);
    }
}
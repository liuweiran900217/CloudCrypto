package cn.edu.buaa.crypto.encryption.hibbe.llw16.generators;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16DecapsulationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16.params.HIBBELLW16SecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generators.PairingKeyDecapsulationGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16KeyDecapsulationGenerator implements PairingKeyDecapsulationGenerator {
    private HIBBELLW16DecapsulationParameters params;

    public void init(CipherParameters params) {
        this.params = (HIBBELLW16DecapsulationParameters)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        HIBBELLW16PublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        HIBBELLW16SecretKeyParameters secretKeyParameters = this.params.getSecretKeyParameters();
        HIBBELLW16CiphertextParameters ciphertextParameters = this.params.getCiphertextParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIdsCT = PairingUtils.MapToZr(pairing, this.params.getIds());

        for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
            if (secretKeyParameters.getIdAt(i) != null &&
                    !secretKeyParameters.getElementIdAt(i).equals(elementIdsCT[i])){
                throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector set");
            }
        }

        Element a0 = secretKeyParameters.getA0().getImmutable();
        Element C0 = ciphertextParameters.getC0().getImmutable();
        Element C1 = ciphertextParameters.getC1().getImmutable();
        Element a1 = secretKeyParameters.getA1().getImmutable();

        for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
            if (secretKeyParameters.getIdAt(i) == null && params.getIdsAt(i) != null) {
                a0 = a0.mul(secretKeyParameters.getBsAt(i).powZn(elementIdsCT[i])).getImmutable();
            }
        }
        Element temp0 = pairing.pairing(C0, a0).getImmutable();
        Element temp1 = pairing.pairing(a1, C1).getImmutable();
        Element sessionKey = temp0.div(temp1).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();
        return Arrays.copyOf(byteArraySessionKey, byteArraySessionKey.length);
    }
}

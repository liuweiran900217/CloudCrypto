package cn.edu.buaa.crypto.encryption.hibbe.llw14.generators;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14DecapsulationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14SecretKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generator.PairingKeyDecapsulationGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW14KeyDecapsulationGenerator implements PairingKeyDecapsulationGenerator {
    private HIBBELLW14DecapsulationParameters params;

    public void init(CipherParameters params) {
        this.params = (HIBBELLW14DecapsulationParameters)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        HIBBELLW14PublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        HIBBELLW14SecretKeyParameters secretKeyParameters = this.params.getSecretKeyParameters();
        HIBBELLW14CiphertextParameters ciphertextParameters = this.params.getCiphertextParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIdsCT = Utils.MapToZr(pairing, this.params.getIds());

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

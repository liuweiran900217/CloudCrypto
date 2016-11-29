package cn.edu.buaa.crypto.encryption.hibbe.llw14.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu prime-order HIBBE decryption generator.
 */
public class HIBBELLW14DecryptionGenerator implements PairingDecryptionGenerator {
    private HIBBEDecryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBBEDecryptionGenerationParameter)params;
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        HIBBELLW14PublicKeySerParameter publicKeyParameters = (HIBBELLW14PublicKeySerParameter)this.params.getPublicKeyParameter();
        HIBBELLW14SecretKeySerParameter secretKeyParameters = (HIBBELLW14SecretKeySerParameter)this.params.getSecretKeyParameter();
        HIBBELLW14CiphertextSerParameter ciphertextParameters = (HIBBELLW14CiphertextSerParameter)this.params.getCiphertextParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIdsCT = PairingUtils.MapStringArrayToGroup(pairing, this.params.getIds(), PairingUtils.PairingGroupType.Zr);

        if (this.params.getIds().length != publicKeyParameters.getMaxUser()
                || secretKeyParameters.getIds().length != publicKeyParameters.getMaxUser()) {
            throw new IllegalArgumentException("Invalid identity vector / identity vector set length");
        }

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
        return ciphertextParameters.getC2().div(sessionKey).getImmutable();
    }
}

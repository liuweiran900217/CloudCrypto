package cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aHeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE decryption generator.
 */
public class HIBBELLW16aDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private HIBBEDecryptionGenerationParameter params;
    private Element sessionKey;

    public void init(CipherParameters params) {
        this.params = (HIBBEDecryptionGenerationParameter)params;
    }

    private void computeDecapsulation() throws InvalidCipherTextException {
        HIBBELLW16aPublicKeySerParameter publicKeyParameters = (HIBBELLW16aPublicKeySerParameter)this.params.getPublicKeyParameter();
        HIBBELLW16aSecretKeySerParameter secretKeyParameters = (HIBBELLW16aSecretKeySerParameter)this.params.getSecretKeyParameter();
        HIBBELLW16aHeaderSerParameter ciphertextParameters = (HIBBELLW16aHeaderSerParameter)this.params.getCiphertextParameter();
        if (this.params.getIds().length != publicKeyParameters.getMaxUser()
                || secretKeyParameters.getIds().length != publicKeyParameters.getMaxUser()) {
            throw new IllegalArgumentException("Invalid identity vector / identity vector set length");
        }
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIdsCT = PairingUtils.MapStringArrayToGroup(pairing, this.params.getIds(), PairingUtils.PairingGroupType.Zr);

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
        this.sessionKey = temp0.div(temp1).getImmutable();
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        HIBBELLW16aCiphertextSerParameter ciphertextParameter = (HIBBELLW16aCiphertextSerParameter)this.params.getCiphertextParameter();
        return ciphertextParameter.getC2().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}

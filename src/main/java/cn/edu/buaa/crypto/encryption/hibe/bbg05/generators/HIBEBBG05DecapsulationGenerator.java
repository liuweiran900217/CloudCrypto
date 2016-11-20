package cn.edu.buaa.crypto.encryption.hibe.bbg05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams.HIBEBBG05DecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Session Key Decapsulation generator for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05DecapsulationGenerator implements PairingDecryptionGenerator {
    private HIBEBBG05DecryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBEBBG05DecryptionGenerationParameter)params;
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        HIBEBBG05PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        HIBEBBG05SecretKeySerParameter secretKeyParameters = this.params.getSecretKeyParameters();
        HIBEBBG05CipherSerParameter ciphertextParameters = this.params.getCiphertextParameters();

        int secretKeyLength = secretKeyParameters.getLength();
        int ciphertextLength = this.params.getLength();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIdsCT = PairingUtils.MapStringArrayToGroup(pairing, this.params.getIds(), PairingUtils.PairingGroupType.Zr);

        if (ciphertextLength < secretKeyLength) {
            throw new InvalidCipherTextException("Secret Key length is longer than Ciphertext length");
        }

        for (int i=0; i<ciphertextLength && i<secretKeyLength; i++){
            if (!secretKeyParameters.getElementIdAt(i).equals(elementIdsCT[i])){
                throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector");
            }
        }

        Element a0 = secretKeyParameters.getA0().getImmutable();
        Element B = ciphertextParameters.getB().getImmutable();
        Element C = ciphertextParameters.getC().getImmutable();
        Element a1 = secretKeyParameters.getA1().getImmutable();
        Element A = ciphertextParameters.getA().getImmutable();

        for (int i=secretKeyParameters.getLength(); i<ciphertextLength; i++){
            a0 = a0.mul(secretKeyParameters.getBsAt(i).powZn(elementIdsCT[i])).getImmutable();
        }
        Element temp0 = pairing.pairing(B, a0).getImmutable();
        Element temp1 = pairing.pairing(a1, C).getImmutable();
        Element sessionKey = temp0.div(temp1).getImmutable();
        return A.div(sessionKey).getImmutable();
    }
}

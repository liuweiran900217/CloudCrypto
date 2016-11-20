package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aCipherSerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters revocation encryption decryption generator.
 */
public class RELSW10aDecryptionGenerator implements PairingDecryptionGenerator {
    private RELSW10aDecryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (RELSW10aDecryptionGenerationParameter)params;
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        RELSW10aPublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        RELSW10aSecretKeySerParameter secretKeyParameters = this.params.getSecretKeyParameters();
        RELSW10aCipherSerParameter ciphertextParameters = this.params.getCiphertextParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        //remove repeated ids
        String[] ids = PairingUtils.removeDuplicates(this.params.getIds());

        Element C1 = pairing.getG1().newOneElement().getImmutable();
        Element C2 = pairing.getG1().newOneElement().getImmutable();

        for (String revokeId : ids) {
            Element elementId = PairingUtils.MapStringToGroup(pairing, revokeId, PairingUtils.PairingGroupType.Zr);
            if (PairingUtils.isEqualElement(secretKeyParameters.getElementId(), elementId)) {
                throw new InvalidCipherTextException("identity associated with the secret key is in the revocation list of the ciphertext");
            }
            C1 = C1.mul(ciphertextParameters.getC1sAt(revokeId).powZn(secretKeyParameters.getElementId().sub(elementId).invert())).getImmutable();
            C2 = C2.mul(ciphertextParameters.getC2sAt(revokeId).powZn(secretKeyParameters.getElementId().sub(elementId).invert())).getImmutable();
        }
        Element sessionKey = pairing.pairing(ciphertextParameters.getC0(), secretKeyParameters.getD0())
                .mul(pairing.pairing(secretKeyParameters.getD1(), C1).mul(pairing.pairing(secretKeyParameters.getD2(), C2)).invert()).getImmutable();
        return ciphertextParameters.getC().div(sessionKey).getImmutable();
    }
}

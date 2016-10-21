package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aCiphertextParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aDecapsulationParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aPublicKeyParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aSecretKeyParameters;
import cn.edu.buaa.crypto.algebra.generators.PairingKeyDecapsulationGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters revocation encryption session key decapsulation generator.
 */
public class RELSW10aKeyDecapsulationGenerator implements PairingKeyDecapsulationGenerator {
    private RELSW10aDecapsulationParameters params;

    public void init(CipherParameters params) {
        this.params = (RELSW10aDecapsulationParameters)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        RELSW10aPublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        RELSW10aSecretKeyParameters secretKeyParameters = this.params.getSecretKeyParameters();
        RELSW10aCiphertextParameters ciphertextParameters = this.params.getCiphertextParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element[] elementIds = PairingUtils.MapToZr(pairing, this.params.getIds());

        for (Element elementId : elementIds) {
            if (PairingUtils.isEqualElement(secretKeyParameters.getElementId(), elementId)) {
                throw new InvalidCipherTextException("identity associated with the secret key is in the revocation list of the ciphertext");
            }
        }

        Element C1 = pairing.getG1().newOneElement().getImmutable();
        Element C2 = pairing.getG1().newOneElement().getImmutable();

        for (int i=0; i<ciphertextParameters.getLength(); i++) {
            C1 = C1.mul(ciphertextParameters.getC1sAt(i).powZn(secretKeyParameters.getElementId().sub(elementIds[i]).invert())).getImmutable();
            C2 = C2.mul(ciphertextParameters.getC2sAt(i).powZn(secretKeyParameters.getElementId().sub(elementIds[i]).invert())).getImmutable();
        }
        Element sessionKey = pairing.pairing(ciphertextParameters.getC0(), secretKeyParameters.getD0())
                .mul(pairing.pairing(secretKeyParameters.getD1(), C1).mul(pairing.pairing(secretKeyParameters.getD2(), C2)).invert()).getImmutable();
        return sessionKey.toBytes();
    }
}

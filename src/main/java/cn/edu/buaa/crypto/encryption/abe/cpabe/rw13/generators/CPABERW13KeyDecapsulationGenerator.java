package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13CiphertextParameters;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13DecapsulationParameters;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params.CPABERW13SecretKeyParameters;
import cn.edu.buaa.crypto.algebra.generators.PairingKeyDecapsulationGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Session Key Decapsulation generator for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13KeyDecapsulationGenerator implements PairingKeyDecapsulationGenerator {
    private CPABERW13DecapsulationParameters params;

    public void init(CipherParameters params) {
        this.params = (CPABERW13DecapsulationParameters) params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        CPABERW13PublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        CPABERW13SecretKeyParameters secretKeyParameters = this.params.getSecretKeyParameters();
        CPABERW13CiphertextParameters ciphertextParameters = this.params.getCiphertextParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        AccessControlEngine accessControlEngine = publicKeyParameters.getAccessControlEngine();
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(
                this.params.getAccessPolicy(), this.params.getRhos());
        try {
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(
                    pairing, secretKeyParameters.getAttributes(), accessControlParameter);

            Element temp = pairing.getGT().newOneElement().getImmutable();
            for (int j = 0; j < this.params.getRhos().length; j++) {
                String attribute = secretKeyParameters.getAttributeAt(j);
                if (omegaElementsMap.containsKey(attribute)) {
                    int i = secretKeyParameters.getIndexWithAttribute(attribute);
                    temp = temp.mul(pairing.pairing(ciphertextParameters.getC1At(i), secretKeyParameters.getK1()))
                            .mul(pairing.pairing(ciphertextParameters.getC2At(i), secretKeyParameters.getK2At(j)))
                            .mul(pairing.pairing(ciphertextParameters.getC3At(i), secretKeyParameters.getK3At(j)))
                            .powZn(omegaElementsMap.get(attribute)).getImmutable();
                }
            }
            Element sessionKey = pairing.pairing(ciphertextParameters.getC0(), secretKeyParameters.getK0()).mul(temp.invert()).getImmutable();
            return sessionKey.toBytes();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attribute set does not satisfy the access policy");
        }
    }
}

package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE decryption generator.
 */
public class CPABERW13DecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    protected CPABEDecryptionGenerationParameter parameter;
    protected Element sessionKey;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEDecryptionGenerationParameter) parameter;
    }

    protected void computeDecapsulation() throws InvalidCipherTextException {
        CPABERW13PublicKeySerParameter publicKeyParameter = (CPABERW13PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        CPABERW13SecretKeySerParameter secretKeyParameter = (CPABERW13SecretKeySerParameter) this.parameter.getSecretKeyParameter();
        CPABERW13HeaderSerParameter ciphertextParameter = (CPABERW13HeaderSerParameter) this.parameter.getCiphertextParameter();

        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);

            this.sessionKey = pairing.pairing(ciphertextParameter.getC0(), secretKeyParameter.getK0());
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element C1 = ciphertextParameter.getC1sAt(attribute);
                Element K1 = secretKeyParameter.getK1();
                Element C2 = ciphertextParameter.getC2sAt(attribute);
                Element K2 = secretKeyParameter.getK2sAt(attribute);
                Element C3 = ciphertextParameter.getC3sAt(attribute);
                Element K3 = secretKeyParameter.getK3sAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                A = A.mul(pairing.pairing(C1, K1).mul(pairing.pairing(C2, K2)).mul(pairing.pairing(C3, K3)).powZn(lambda)).getImmutable();
            }
            sessionKey = sessionKey.div(A).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        CPABERW13CiphertextSerParameter ciphertextParameter = (CPABERW13CiphertextSerParameter) this.parameter.getCiphertextParameter();
            return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}

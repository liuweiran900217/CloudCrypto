package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE decryption generator.
 */
public class CPABEBSW07DecryptionGenerator implements PairingDecryptionGenerator {
    private CPABEDecryptionGenerationParameter parameter;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEDecryptionGenerationParameter) parameter;
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        CPABEBSW07PublicKeySerParameter publicKeyParameter = (CPABEBSW07PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        CPABEBSW07SecretKeySerParameter secretKeyParameter = (CPABEBSW07SecretKeySerParameter) this.parameter.getSecretKeyParameter();
        CPABEBSW07CiphertextSerParameter ciphertextParameter = (CPABEBSW07CiphertextSerParameter) this.parameter.getCiphertextParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, secretKeyParameter.getAttributes(), accessControlParameter);
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element D1 = secretKeyParameter.getD1sAt(attribute);
                Element D2 = secretKeyParameter.getD2sAt(attribute);
                Element C1 = ciphertextParameter.getC1sAt(attribute);
                Element C2 = ciphertextParameter.getC2sAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                A = A.mul(pairing.pairing(D1, C1).div(pairing.pairing(D2, C2)).powZn(lambda)).getImmutable();
            }
            Element sessionKey = pairing.pairing(ciphertextParameter.getC(), secretKeyParameter.getD()).div(A).getImmutable();
            return ciphertextParameter.getCPrime().div(sessionKey).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }
}

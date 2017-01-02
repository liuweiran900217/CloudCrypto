package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

/**
 * Created by Weran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE decryption generator.
 */
public class KPABEHW14DecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    protected KPABEDecryptionGenerationParameter parameter;
    protected Element sessionKey;

    public void init(CipherParameters params) {
        this.parameter = (KPABEDecryptionGenerationParameter)params;
    }

    protected void computeDecapsulation() throws InvalidCipherTextException {
        KPABEHW14PublicKeySerParameter publicKeyParameter = (KPABEHW14PublicKeySerParameter)this.parameter.getPublicKeyParameter();
        KPABEHW14SecretKeySerParameter secretKeyParameter = (KPABEHW14SecretKeySerParameter)this.parameter.getSecretKeyParameter();
        KPABEHW14HeaderSerParameter ciphertextParameter = (KPABEHW14HeaderSerParameter)this.parameter.getCiphertextParameter();
        AccessControlParameter accessControlParameter = secretKeyParameter.getAccessControlParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, attributes, accessControlParameter);
            this.sessionKey = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element C0 = ciphertextParameter.getC0();
                Element K0 = secretKeyParameter.getK0sAt(attribute);
                Element C1 = ciphertextParameter.getC1sAt(attribute);
                Element K1 = secretKeyParameter.getK1sAt(attribute);
                Element C2 = ciphertextParameter.getC2sAt(attribute).mul(publicKeyParameter.getU().powZn(ciphertextParameter.getC3sAt(attribute)));
                Element K2 = secretKeyParameter.getK2sAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                sessionKey = sessionKey.mul(pairing.pairing(C0, K0).mul(pairing.pairing(C1, K1)).mul(pairing.pairing(C2, K2)).powZn(lambda)).getImmutable();
            }
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        KPABEHW14CiphertextSerParameter ciphertextParameter = (KPABEHW14CiphertextSerParameter)this.parameter.getCiphertextParameter();
        return ciphertextParameter.getC().div(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}

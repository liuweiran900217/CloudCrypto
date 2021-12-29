package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.algebra.generators.PairingReEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEReEncGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

public class CPABERW13ReEncryptionGenerator implements PairingReEncryptionGenerator {

    private CPABERW13PublicKeySerParameter publicKeyParameter;
    protected CPABEReEncGenerationParameter parameter;
    protected AccessControlParameter accessControlParameter;
    protected Element sessionKey;
    protected Element C_;
    protected Element C0_;
    protected Element C1_;
    protected Element C2_;
    protected Element C3_;

    public void init(CipherParameters params) {
        this.parameter = (CPABEReEncGenerationParameter) params;
        this.publicKeyParameter = (CPABERW13PublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    protected void computeEncapsulation() throws InvalidCipherTextException {
        CPABERW13PublicKeySerParameter publicKeyParameter =
                (CPABERW13PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        CPABERW13ReKeySerParameter reKeyParameter =
                (CPABERW13ReKeySerParameter) this.parameter.getReKeyParameter();
        CPABERW13CiphertextSerParameter ciphertextParameter =
                (CPABERW13CiphertextSerParameter) this.parameter.getCipherParameter();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        try {
            AccessControlParameter accessControlParameter
                    = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing,
                    reKeyParameter.getAttributes(), accessControlParameter);

            // reCiphertext.B
            this.sessionKey = pairing.pairing(ciphertextParameter.getC0(), reKeyParameter.getD0());
            Element A = pairing.getGT().newOneElement().getImmutable();
            for (String attribute : omegaElementsMap.keySet()) {
                Element C1 = ciphertextParameter.getC1sAt(attribute);
                Element d1 = reKeyParameter.getD1();
                Element C2 = ciphertextParameter.getC2sAt(attribute);
                Element d2 = reKeyParameter.getD2sAt(attribute);
                Element C3 = ciphertextParameter.getC3sAt(attribute);
                Element d3 = reKeyParameter.getD3sAt(attribute);
                Element lambda = omegaElementsMap.get(attribute);
                A = A.mul(pairing.pairing(C1, d1).mul(pairing.pairing(C2, d2)).mul(pairing.pairing(C3, d3)).powZn(lambda)).getImmutable();
            }
            sessionKey = sessionKey.div(A).getImmutable();
        } catch (UnsatisfiedAccessControlException e) {
            throw new InvalidCipherTextException("Attributes associated with the ciphertext do not satisfy access policy associated with the secret key.");
        }
        this.C_ = ciphertextParameter.getC().div(sessionKey).getImmutable();
        this.C0_ = reKeyParameter.getD4();
        this.C1_ = reKeyParameter.getD5();
        this.C2_ = reKeyParameter.getD6();
        this.C3_ = ciphertextParameter.getC4();
    }

    public PairingCipherSerParameter generateCiphertext() throws InvalidCipherTextException {
        computeEncapsulation();
        CPABERW13CiphertextSerParameter ciphertextParameter =
                (CPABERW13CiphertextSerParameter) this.parameter.getCipherParameter();
        Element C_ = ciphertextParameter.getC().div(this.sessionKey).getImmutable();
        return new CPABERW13ReEncCiphertextSerParameter(publicKeyParameter.getParameters(), C_, C0_, C1_, C2_, C3_);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() throws InvalidCipherTextException {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new CPABERW13ReEncHeaderSerParameter(publicKeyParameter.getParameters(), C0_, C1_, C2_, C3_));
    }
}

package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE encryption generator.
 */
public class CPABEHW14EncryptionGenerator  implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private CPABEHW14PublicKeySerParameter publicKeyParameter;
    private CPABEHW14IntermediateSerParameter intermediate;
    protected CPABEEncryptionGenerationParameter parameter;
    protected AccessControlParameter accessControlParameter;
    protected Element s;
    protected Element sessionKey;
    protected Element C0;
    protected Map<String, Element> C1s;
    protected Map<String, Element> C2s;
    protected Map<String, Element> C3s;
    protected Map<String, Element> C4s;
    protected Map<String, Element> C5s;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEEncryptionGenerationParameter) parameter;
        this.publicKeyParameter = (CPABEHW14PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        if (this.parameter.isIntermediateGeneration()) {
            this.intermediate = (CPABEHW14IntermediateSerParameter)this.parameter.getIntermediate();
        }
    }

    protected void computeEncapsulation() {
        int[][] accessPolicy = this.parameter.getAccessPolicy();
        String[] rhos = this.parameter.getRhos();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        this.accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        if (this.parameter.isIntermediateGeneration()) {
            this.s = this.intermediate.getS().getImmutable();
            this.sessionKey = this.intermediate.getSessionKey().getImmutable();
            this.C0 = this.intermediate.getC0().getImmutable();
            Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
            if (lambdas.keySet().size() > this.intermediate.getN()) {
                throw new IllegalArgumentException("Intermediate size smaller than the number of rhos");
            }
            this.C1s = new HashMap<String, Element>();
            this.C2s = new HashMap<String, Element>();
            this.C3s = new HashMap<String, Element>();
            this.C4s = new HashMap<String, Element>();
            this.C5s = new HashMap<String, Element>();
            int index = 0;
            for (String rho : lambdas.keySet()) {
                Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
                C1s.put(rho, this.intermediate.getC1sAt(index).getImmutable());
                C2s.put(rho, this.intermediate.getC2sAt(index).getImmutable());
                C3s.put(rho, this.intermediate.getC3sAt(index).getImmutable());
                C4s.put(rho, lambdas.get(rho).sub(this.intermediate.getLambdasAt(index)).getImmutable());
                C5s.put(rho, this.intermediate.getTsAt(index).mulZn(this.intermediate.getXsAt(index).sub(elementRho)).getImmutable());
                index++;
            }

        } else {
            this.s = pairing.getZr().newRandomElement().getImmutable();
            this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
            this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();

            Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
            this.C1s = new HashMap<String, Element>();
            this.C2s = new HashMap<String, Element>();
            this.C3s = new HashMap<String, Element>();
            this.C4s = new HashMap<String, Element>();
            this.C5s = new HashMap<String, Element>();
            for (String rho : lambdas.keySet()) {
                Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
                Element ti = pairing.getZr().newRandomElement().getImmutable();
                C1s.put(rho, publicKeyParameter.getW().powZn(lambdas.get(rho)).mul(publicKeyParameter.getV().powZn(ti)).getImmutable());
                C2s.put(rho, publicKeyParameter.getU().powZn(elementRho).mul(publicKeyParameter.getH()).powZn(ti.negate()).getImmutable());
                C3s.put(rho, publicKeyParameter.getG().powZn(ti).getImmutable());
                C4s.put(rho, pairing.getZr().newZeroElement().getImmutable());
                C5s.put(rho, pairing.getZr().newZeroElement().getImmutable());
            }
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new CPABEHW14CiphertextSerParameter(publicKeyParameter.getParameters(), C, C0, C1s, C2s, C3s, C4s, C5s);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new CPABEHW14HeaderSerParameter(publicKeyParameter.getParameters(), C0, C1s, C2s, C3s, C4s, C5s)
        );
    }
}

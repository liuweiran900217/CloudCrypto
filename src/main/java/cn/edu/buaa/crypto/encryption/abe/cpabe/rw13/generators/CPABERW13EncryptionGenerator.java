package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE encryption generator.
 */
public class CPABERW13EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private CPABERW13PublicKeySerParameter publicKeyParameter;
    protected CPABEEncryptionGenerationParameter parameter;
    protected AccessControlParameter accessControlParameter;
    protected Element s;
    protected Element sessionKey;
    protected Element C0;
    protected Map<String, Element> C1s;
    protected Map<String, Element> C2s;
    protected Map<String, Element> C3s;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEEncryptionGenerationParameter) parameter;
        this.publicKeyParameter = (CPABERW13PublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    protected void computeEncapsulation() {
        int[][] accessPolicy = this.parameter.getAccessPolicy();
        String[] rhos = this.parameter.getRhos();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        this.accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        this.s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
        this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();

        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);
        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        this.C3s = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            Element elementRho = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            Element ti = pairing.getZr().newRandomElement().getImmutable();
            C1s.put(rho, publicKeyParameter.getW().powZn(lambdas.get(rho)).mul(publicKeyParameter.getV().powZn(ti)).getImmutable());
            C2s.put(rho, publicKeyParameter.getU().powZn(elementRho).mul(publicKeyParameter.getH()).powZn(ti.negate()).getImmutable());
            C3s.put(rho, publicKeyParameter.getG().powZn(ti).getImmutable());
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new CPABERW13CiphertextSerParameter(publicKeyParameter.getParameters(), C, C0, C1s, C2s, C3s);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new CPABERW13HeaderSerParameter(publicKeyParameter.getParameters(), C0, C1s, C2s, C3s)
        );
    }
}
package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE encryption generator.
 */
public class KPABEHW14EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private KPABEHW14PublicKeySerParameter publicKeyParameter;
    private KPABEHW14IntermediateSerParameter intermedate;
    protected KPABEEncryptionGenerationParameter parameter;
    protected String[] attributes;
    protected Element s;
    protected Element sessionKey;
    protected Element C0;
    protected Map<String, Element> C1s;
    protected Map<String, Element> C2s;
    protected Map<String, Element> C3s;

    public void init(CipherParameters params) {
        this.parameter = (KPABEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (KPABEHW14PublicKeySerParameter)this.parameter.getPublicKeyParameter();
        if (this.parameter.isIntermediateGeneration()) {
            this.intermedate = (KPABEHW14IntermediateSerParameter)this.parameter.getIntermediate();
        }
    }

    protected void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] attributes = this.parameter.getAttributes();
        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        this.C3s = new HashMap<String, Element>();

        if (this.intermedate != null) {
            if (attributes.length > this.intermedate.getN()) {
                throw new IllegalArgumentException("Intermediate size smaller than the number of attributes");
            }
            this.s = this.intermedate.getS().getImmutable();
            this.sessionKey = this.intermedate.getSessionKey().getImmutable();
            this.C0 = this.intermedate.getC0().getImmutable();
            int index = 0;
            for (String attribute : attributes) {
                Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
                C1s.put(attribute, this.intermedate.getC1sAt(index).getImmutable());
                C2s.put(attribute, this.intermedate.getC2sAt(index).getImmutable());
                C3s.put(attribute, this.intermedate.getRsAt(index).mulZn(elementAttribute.sub(this.intermedate.getXsAt(index))).getImmutable());
                index++;
            }
        } else {
            this.s = pairing.getZr().newRandomElement().getImmutable();
            this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
            this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();
            for (String attribute : attributes) {
                Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
                Element ri = pairing.getZr().newRandomElement().getImmutable();
                Element C1 = publicKeyParameter.getG().powZn(ri).getImmutable();
                C1s.put(attribute, C1);
                Element C2 = publicKeyParameter.getU().powZn(elementAttribute).mul(publicKeyParameter.getH()).powZn(ri)
                        .mul(publicKeyParameter.getW().powZn(s.negate())).getImmutable();
                C2s.put(attribute, C2);
                C3s.put(attribute, pairing.getZr().newZeroElement().getImmutable());
            }
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new KPABEHW14CiphertextSerParameter(publicKeyParameter.getParameters(), C, C0, C1s, C2s, C3s);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new KPABEHW14HeaderSerParameter(publicKeyParameter.getParameters(), C0, C1s, C2s, C3s)
        );
    }
}
package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13EncryptionGenerator;
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
public class KPABEHW14EncryptionGenerator extends KPABERW13EncryptionGenerator {
    private KPABEHW14PublicKeySerParameter publicKeyParameter;
    private KPABEHW14IntermediateSerParameter intermedate;
    protected String[] attributes;
    protected Map<String, Element> C3s;

    public void init(CipherParameters params) {
        this.parameter = (KPABEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (KPABEHW14PublicKeySerParameter)this.parameter.getPublicKeyParameter();
        if (this.parameter.isIntermediateGeneration()) {
            this.intermedate = (KPABEHW14IntermediateSerParameter)this.parameter.getIntermediate();
        }
        super.init(params);
    }

    protected void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] attributes = this.parameter.getAttributes();
        this.C3s = new HashMap<String, Element>();

        if (this.intermedate != null) {
            if (attributes.length > this.intermedate.getN()) {
                throw new IllegalArgumentException("Intermediate size smaller than the number of attributes");
            }
            this.C1s = new HashMap<String, Element>();
            this.C2s = new HashMap<String, Element>();
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
            super.computeEncapsulation();
            for (String attribute : attributes) {
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
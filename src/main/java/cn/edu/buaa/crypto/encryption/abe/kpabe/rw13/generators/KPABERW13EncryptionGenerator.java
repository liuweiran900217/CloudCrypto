package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Rouselakis-Waters KP-ABE encryption generator.
 */
public class KPABERW13EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {

    protected KPABEEncryptionGenerationParameter parameter;
    private KPABERW13PublicKeySerParameter publicKeyParameter;
    protected Element s;
    protected Element sessionKey;
    protected Element C0;
    protected Map<String, Element> C1s;
    protected Map<String, Element> C2s;

    public void init(CipherParameters params) {
        this.parameter = (KPABEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (KPABERW13PublicKeySerParameter)this.parameter.getPublicKeyParameter();
    }

    protected void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] attributes = this.parameter.getAttributes();
        this.s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
        this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();
        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Element C1 = publicKeyParameter.getG().powZn(ri).getImmutable();
            C1s.put(attribute, C1);
            Element C2 = publicKeyParameter.getU().powZn(elementAttribute).mul(publicKeyParameter.getH()).powZn(ri)
                    .mul(publicKeyParameter.getW().powZn(s.negate())).getImmutable();
            C2s.put(attribute, C2);
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new KPABERW13CiphertextSerParameter(publicKeyParameter.getParameters(), C, C0, C1s, C2s);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new KPABERW13HeaderSerParameter(publicKeyParameter.getParameters(), C0, C1s, C2s)
        );
    }
}
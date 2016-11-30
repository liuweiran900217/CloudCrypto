package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles encryption generator.
 */
public class KPABEGPSW06bEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {

    private KPABEEncryptionGenerationParameter params;
    private KPABEGPSW06bPublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Element E2;
    private Map<String, Element> Es;

    public void init(CipherParameters params) {
        this.params = (KPABEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (KPABEGPSW06bPublicKeySerParameter)this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] attributes = this.params.getAttributes();
        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = pairing.pairing(publicKeyParameter.getG1(), publicKeyParameter.getG2()).powZn(s).getImmutable();
        this.E2 = publicKeyParameter.getG().powZn(s).getImmutable();
        this.Es = new HashMap<String, Element>();
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.G1);
            Element E = elementAttribute.powZn(s).getImmutable();
            Es.put(attribute, E);
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element E1 = this.sessionKey.mul(this.params.getMessage()).getImmutable();
        return new KPABEGPSW06bCiphertextSerParameter(publicKeyParameter.getParameters(), E1, E2, Es);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new KPABEGPSW06bHeaderSerParameter(publicKeyParameter.getParameters(), E2, Es)
        );
    }
}

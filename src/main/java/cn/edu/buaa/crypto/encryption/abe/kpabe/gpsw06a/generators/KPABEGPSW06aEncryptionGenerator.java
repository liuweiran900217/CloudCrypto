package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE encryption generator.
 */
public class KPABEGPSW06aEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private KPABEEncryptionGenerationParameter params;

    private KPABEGPSW06aPublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Map<String, Element> Es;

    public void init(CipherParameters params) {
        this.params = (KPABEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (KPABEGPSW06aPublicKeySerParameter)this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] attributes = this.params.getAttributes();
        assert(attributes.length <= publicKeyParameter.getMaxAttributesNum());
        if (attributes.length > publicKeyParameter.getMaxAttributesNum()) {
            throw new IllegalArgumentException("# of broadcast receiver set " + attributes.length +
                    " is greater than the maximal number of receivers " + publicKeyParameter.getMaxAttributesNum());
        }

        try {
            Element s = pairing.getZr().newRandomElement().getImmutable();
            this.sessionKey = publicKeyParameter.getY().powZn(s).getImmutable();
            this.Es = new HashMap<String, Element>();
            for (String attribute : attributes) {
                int index = Integer.parseInt(attribute);
                if (index >= publicKeyParameter.getMaxAttributesNum() || index < 0) {
                    throw new InvalidParameterException("Rho index greater than or equal to the max number of attributes supported");
                }
                Element E = publicKeyParameter.getTsAt(String.valueOf(index)).powZn(s).getImmutable();
                Es.put(String.valueOf(index), E);
            }
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element EPrime = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new KPABEGPSW06aCiphertextSerParameter(publicKeyParameter.getParameters(), EPrime, Es);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new KPABEGPSW06aHeaderSerParameter(publicKeyParameter.getParameters(), Es)
        );
    }
}
package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aCiphertextSerParameter;
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
public class KPABEGPSW06aEncryptionGenerator implements PairingEncryptionGenerator {

    private KPABEEncryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (KPABEEncryptionGenerationParameter)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        KPABEGPSW06aPublicKeySerParameter publicKeyParameter = (KPABEGPSW06aPublicKeySerParameter)this.params.getPublicKeyParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] attributes = this.params.getAttributes();
        assert(attributes.length <= publicKeyParameter.getMaxAttributesNum());
        Element message = this.params.getMessage();
        if (attributes.length > publicKeyParameter.getMaxAttributesNum()) {
            throw new IllegalArgumentException("# of broadcast receiver set " + attributes.length +
                    " is greater than the maximal number of receivers " + publicKeyParameter.getMaxAttributesNum());
        }

        try {
            Element s = pairing.getZr().newRandomElement().getImmutable();
            Element sessionKey = publicKeyParameter.getY().powZn(s).getImmutable();
            Element EPrime = sessionKey.mul(message).getImmutable();
            Map<String, Element> Es = new HashMap<String, Element>();
            for (String attribute : attributes) {
                int index = Integer.parseInt(attribute);
                if (index >= publicKeyParameter.getMaxAttributesNum() || index < 0) {
                    throw new InvalidParameterException("Rho index greater than or equal to the max number of attributes supported");
                }
                Element E = publicKeyParameter.getTsAt(String.valueOf(index)).powZn(s).getImmutable();
                Es.put(String.valueOf(index), E);
            }

            return new KPABEGPSW06aCiphertextSerParameter(publicKeyParameter.getParameters(), EPrime, Es);
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }
}
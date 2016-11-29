package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams.KPABEGPSW06bPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.security.InvalidParameterException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles encryption generator.
 */
public class KPABEGPSW06bEncryptionGenerator implements PairingEncryptionGenerator {

    private KPABEEncryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (KPABEEncryptionGenerationParameter)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        KPABEGPSW06bPublicKeySerParameter publicKeyParameter = (KPABEGPSW06bPublicKeySerParameter)this.params.getPublicKeyParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] attributes = this.params.getAttributes();
        Element message = this.params.getMessage();

        try {
            Element s = pairing.getZr().newRandomElement().getImmutable();
            Element sessionKey = pairing.pairing(publicKeyParameter.getG1(), publicKeyParameter.getG2()).powZn(s).getImmutable();
            Element E1 = sessionKey.mul(message).getImmutable();
            Element E2 = publicKeyParameter.getG().powZn(s).getImmutable();
            Map<String, Element> Es = new HashMap<String, Element>();
            for (String attribute : attributes) {
                Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.G1);
                Element E = elementAttribute.powZn(s).getImmutable();
                Es.put(attribute, E);
            }
            return new KPABEGPSW06bCiphertextSerParameter(publicKeyParameter.getParameters(), E1, E2, Es);
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }
}

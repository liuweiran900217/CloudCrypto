package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams.KPABEGPSW06aCiphertextGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.security.InvalidParameterException;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE session key / ciphertext pair generator.
 */
public class KPABEGPSW06aEncapsulationPairGenerator  implements PairingEncapsulationPairGenerator {

    private KPABEGPSW06aCiphertextGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (KPABEGPSW06aCiphertextGenerationParameter)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        KPABEGPSW06aPublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] attributes = this.params.getAttributes();
        if (attributes.length > publicKeyParameters.getMaxAttributesNum()) {
            throw new IllegalArgumentException("# of broadcast receiver set " + attributes.length +
                    " is greater than the maximal number of receivers " + publicKeyParameters.getMaxAttributesNum());
        }

        try {
            Element s = pairing.getZr().newRandomElement().getImmutable();
            Element sessionKey = publicKeyParameters.getY().powZn(s).getImmutable();
            byte[] byteArraySessionKey = sessionKey.toBytes();
            Element[] Es = new Element[publicKeyParameters.getMaxAttributesNum()];
            for (String attribute : attributes) {
                int index = Integer.parseInt(attribute);
                if (index >= publicKeyParameters.getMaxAttributesNum() || index < 0) {
                    throw new InvalidParameterException("Rho index greater than or equal to the max number of attributes supported");
                }
                Es[index] = publicKeyParameters.getTsAt(index).powZn(s).getImmutable();
            }

            return new PairingKeyEncapsulationSerPair(
                    byteArraySessionKey,
                    new KPABEGPSW06aCipherSerParameter(publicKeyParameters.getParameters(), Es));
        } catch (NumberFormatException e) {
            throw new InvalidParameterException("Invalid rhos, require rhos represented by integers");
        }
    }
}
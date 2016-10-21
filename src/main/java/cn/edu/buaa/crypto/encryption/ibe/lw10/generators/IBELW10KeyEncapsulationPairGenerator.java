package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10CiphertextGenerationParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10CiphertextParameters;
import cn.edu.buaa.crypto.encryption.ibe.lw10.params.IBELW10PublicKeyParameters;
import cn.edu.buaa.crypto.algebra.generators.PairingKeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.params.PairingKeyEncapsulationPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Lewko-Waters IBE ciphertext / session key pair generator.
 */
public class IBELW10KeyEncapsulationPairGenerator  implements PairingKeyEncapsulationPairGenerator {

    private IBELW10CiphertextGenerationParameters params;

    public void init(CipherParameters params) {
        this.params = (IBELW10CiphertextGenerationParameters)params;
    }

    public PairingKeyEncapsulationPair generateEncryptionPair() {
        IBELW10PublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String id = this.params.getId();
        Element elementId = PairingUtils.MapToZr(pairing, id).getImmutable();

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = publicKeyParameters.getEggAlpha().powZn(s).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();

        Element C1 = publicKeyParameters.getU().powZn(elementId).mul(publicKeyParameters.getH()).powZn(s).getImmutable();
        Element C2 = publicKeyParameters.getG().powZn(s).getImmutable();

        return new PairingKeyEncapsulationPair(
                byteArraySessionKey,
                new IBELW10CiphertextParameters(publicKeyParameters.getParameters(), C1, C2));
    }
}

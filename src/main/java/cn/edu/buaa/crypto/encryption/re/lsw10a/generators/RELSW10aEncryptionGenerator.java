package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aCipherSerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters revocation encryption generator.
 */
public class RELSW10aEncryptionGenerator implements PairingEncryptionGenerator {
    private RELSW10aEncryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (RELSW10aEncryptionGenerationParameter)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        RELSW10aPublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element s = pairing.getZr().newZeroElement().getImmutable();

        Map<String, Element> C1s = new HashMap<String, Element>();
        Map<String, Element> C2s = new HashMap<String, Element>();
        for (String revokeId : this.params.getIds()) {
            Element elementId = PairingUtils.MapStringToGroup(pairing, revokeId, PairingUtils.PairingGroupType.Zr);
            Element ss = pairing.getZr().newRandomElement().getImmutable();
            C1s.put(revokeId, publicKeyParameters.getGb().powZn(ss).getImmutable());
            C2s.put(revokeId, publicKeyParameters.getGb2().powZn(elementId).mul(publicKeyParameters.getHb()).powZn(ss).getImmutable());
            s = s.add(ss).getImmutable();
        }

        Element sessionKey = publicKeyParameters.getEggAlpha().powZn(s).getImmutable();
        Element C = sessionKey.mul(this.params.getMessage()).getImmutable();
        Element C0 = publicKeyParameters.getG().powZn(s).getImmutable();

        return new RELSW10aCipherSerParameter(publicKeyParameters.getParameters(), C, C0, C1s, C2s);
    }
}

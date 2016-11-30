package cn.edu.buaa.crypto.encryption.re.lsw10a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aHeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.re.genparams.REEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aCiphertextSerParameter;
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
public class RELSW10aEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private REEncryptionGenerationParameter params;

    private Element sessionKey;
    private RELSW10aPublicKeySerParameter publicKeyParameter;
    private Element C0;
    private Map<String, Element> C1s;
    private Map<String, Element> C2s;

    public void init(CipherParameters params) {
        this.params = (REEncryptionGenerationParameter)params;
        this.publicKeyParameter = (RELSW10aPublicKeySerParameter)this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element s = pairing.getZr().newZeroElement().getImmutable();

        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        for (String revokeId : this.params.getIds()) {
            Element elementId = PairingUtils.MapStringToGroup(pairing, revokeId, PairingUtils.PairingGroupType.Zr);
            Element ss = pairing.getZr().newRandomElement().getImmutable();
            C1s.put(revokeId, publicKeyParameter.getGb().powZn(ss).getImmutable());
            C2s.put(revokeId, publicKeyParameter.getGb2().powZn(elementId).mul(publicKeyParameter.getHb()).powZn(ss).getImmutable());
            s = s.add(ss).getImmutable();
        }

        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
        this.C0 = publicKeyParameter.getG().powZn(s).getImmutable();
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.params.getMessage()).getImmutable();
        return new RELSW10aCiphertextSerParameter(publicKeyParameter.getParameters(), C, C0, C1s, C2s);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new RELSW10aHeaderSerParameter(publicKeyParameter.getParameters(), C0, C1s, C2s)
        );
    }
}

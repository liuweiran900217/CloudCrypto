package cn.edu.buaa.crypto.encryption.re.llw16a.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.re.genparams.REEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aIntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aEncryptionGenerator;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CPA-secure RE encryption generator.
 */
public class RELLW16aEncryptionGenerator extends RELSW10aEncryptionGenerator {
    private RELLW16aPublicKeySerParameter publicKeyParameter;
    private RELLW16aIntermediateSerParameter intermediate;
    protected Map<String, Element> C3s;

    public void init(CipherParameters params) {
        this.parameter = (REEncryptionGenerationParameter)params;
        this.publicKeyParameter = (RELLW16aPublicKeySerParameter)this.parameter.getPublicKeyParameter();
        if (this.parameter.isIntermediateGeneration()) {
            this.intermediate = (RELLW16aIntermediateSerParameter)this.parameter.getIntermediate();
        }
        super.init(params);
    }

    protected void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] revokeIds = this.parameter.getIds();
        this.C3s = new HashMap<String, Element>();

        if (this.intermediate != null) {
            if (revokeIds.length > this.intermediate.getN()) {
                throw new IllegalArgumentException("Intermediate size does not match the number of revoke identities");
            }
            this.C1s = new HashMap<String, Element>();
            this.C2s = new HashMap<String, Element>();
            this.s = this.intermediate.getS().getImmutable();
            this.sessionKey = this.intermediate.getSessionKey().getImmutable();
            this.C0 = this.intermediate.getC0().getImmutable();
            int index = 0;
            for (String revokeId : revokeIds) {
                Element elementRevokeId = PairingUtils.MapStringToGroup(pairing, revokeId, PairingUtils.PairingGroupType.Zr);
                C1s.put(revokeId, this.intermediate.getC1sAt(index).getImmutable());
                C2s.put(revokeId, this.intermediate.getC2sAt(index).getImmutable());
                C3s.put(revokeId, this.intermediate.getSsAt(index).mulZn(elementRevokeId.sub(this.intermediate.getXsAt(index))).getImmutable());
                index++;
            }
        } else {
            super.computeEncapsulation();
            for (String revokeId : revokeIds) {
                C3s.put(revokeId, pairing.getZr().newZeroElement().getImmutable());
            }
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new RELLW16aCiphertextSerParameter(publicKeyParameter.getParameters(), C, C0, C1s, C2s, C3s);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new RELLW16aHeaderSerParameter(publicKeyParameter.getParameters(), C0, C1s, C2s, C3s)
        );
    }
}

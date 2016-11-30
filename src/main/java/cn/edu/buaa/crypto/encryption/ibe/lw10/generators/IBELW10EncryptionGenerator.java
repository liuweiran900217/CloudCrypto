package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10HeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 16/5/7.
 *
 * Lewko-Waters IBE encryption generator.
 */
public class IBELW10EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {

    private IBEEncryptionGenerationParameter params;
    private IBELW10PublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Element C1;
    private Element C2;

    public void init(CipherParameters params) {
        this.params = (IBEEncryptionGenerationParameter) params;
        this.publicKeyParameter = (IBELW10PublicKeySerParameter) this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String id = this.params.getId();
        Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();

        this.C1 = publicKeyParameter.getU().powZn(elementId).mul(publicKeyParameter.getH()).powZn(s).getImmutable();
        this.C2 = publicKeyParameter.getG().powZn(s).getImmutable();
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(this.sessionKey.toBytes(),
                new IBELW10HeaderSerParameter(publicKeyParameter.getParameters(), C1, C2));
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C0 = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new IBELW10CiphertextSerParameter(publicKeyParameter.getParameters(), C0, C1, C2);
    }
}

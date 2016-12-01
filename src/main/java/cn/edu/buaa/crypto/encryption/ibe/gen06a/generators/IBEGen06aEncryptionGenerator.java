package cn.edu.buaa.crypto.encryption.ibe.gen06a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CPA-secure IBE encryption generator.
 */
public class IBEGen06aEncryptionGenerator  implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {

    private IBEEncryptionGenerationParameter params;
    private IBEGen06aPublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Element u;
    private Element v;

    public void init(CipherParameters params) {
        this.params = (IBEEncryptionGenerationParameter) params;
        this.publicKeyParameter = (IBEGen06aPublicKeySerParameter) this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String id = this.params.getId();
        Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getH()).powZn(s).getImmutable();
        this.u = publicKeyParameter.getG1().powZn(s).mul(publicKeyParameter.getG().powZn(elementId.mul(s).negate())).getImmutable();
        this.v = pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getG()).powZn(s).getImmutable();
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(this.sessionKey.toBytes(),
                new IBEGen06aHeaderSerParameter(publicKeyParameter.getParameters(), u, v));
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element w = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new IBEGen06aCiphertextSerParameter(publicKeyParameter.getParameters(), u, v, w);
    }
}
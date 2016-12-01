package cn.edu.buaa.crypto.encryption.ibe.bf01a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE encryption generator.
 */
public class IBEBF01aEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {

    private IBEEncryptionGenerationParameter params;
    private IBEBF01aPublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Element U;

    public void init(CipherParameters params) {
        this.params = (IBEEncryptionGenerationParameter) params;
        this.publicKeyParameter = (IBEBF01aPublicKeySerParameter) this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String id = this.params.getId();
        Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingUtils.PairingGroupType.G1).getImmutable();

        Element r = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = PairingUtils.MapByteArrayToGroup(
                pairing,
                pairing.pairing(elementId, publicKeyParameter.getGs()).powZn(r).toBytes(),
                PairingUtils.PairingGroupType.GT);
        this.U = publicKeyParameter.getG().powZn(r).getImmutable();
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(this.sessionKey.toBytes(),
                new IBEBF01aHeaderSerParameter(publicKeyParameter.getParameters(), U));
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element V = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new IBEBF01aCiphertextSerParameter(publicKeyParameter.getParameters(), U, V);
    }
}
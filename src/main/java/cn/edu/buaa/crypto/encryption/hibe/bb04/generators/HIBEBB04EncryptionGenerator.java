package cn.edu.buaa.crypto.encryption.hibe.bb04.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Boneh-Boyen HIBE encryption generator.
 */
public class HIBEBB04EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {

    private HIBEEncryptionGenerationParameter params;

    private HIBEBB04PublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Element B;
    private Element[] Cs;

    public void init(CipherParameters params) {
        this.params = (HIBEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (HIBEBB04PublicKeySerParameter)this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = pairing.pairing(publicKeyParameter.getG1(), publicKeyParameter.getG2()).powZn(s).getImmutable();

        this.B = publicKeyParameter.getG().powZn(s).getImmutable();
        this.Cs = new Element[ids.length];
        for (int i = 0; i < Cs.length; i++){
            Cs[i] = publicKeyParameter.getG1().powZn(elementIds[i]).mul(publicKeyParameter.getHsAt(i)).powZn(s).getImmutable();
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element A = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new HIBEBB04CiphertextSerParameter(publicKeyParameter.getParameters(), A, B, Cs);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new HIBEBB04HeaderSerParameter(publicKeyParameter.getParameters(), B, Cs));
    }
}

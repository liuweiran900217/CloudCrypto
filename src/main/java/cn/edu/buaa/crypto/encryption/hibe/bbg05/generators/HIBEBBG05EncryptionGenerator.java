package cn.edu.buaa.crypto.encryption.hibe.bbg05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.genparams.HIBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Ciphertext Encapsulation generator for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05EncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private HIBEEncryptionGenerationParameter params;

    private HIBEBBG05PublicKeySerParameter publicKeyParameter;
    private Element sessionKey;
    private Element B;
    private Element C;

    public void init(CipherParameters params) {
        this.params = (HIBEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (HIBEBBG05PublicKeySerParameter)this.params.getPublicKeyParameter();
        assert(this.params.getLength() <= publicKeyParameter.getMaxLength());
    }

    private void computeEncapsulation() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.sessionKey = pairing.pairing(publicKeyParameter.getG1(), publicKeyParameter.getG2()).powZn(s).getImmutable();

        this.B = publicKeyParameter.getG().powZn(s).getImmutable();
        this.C = publicKeyParameter.getG3().getImmutable();
        for (int i=0; i<this.params.getLength(); i++){
            C = C.mul(publicKeyParameter.getHsAt(i).powZn(elementIds[i])).getImmutable();
        }
        C = C.powZn(s).getImmutable();
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element A = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new HIBEBBG05CiphertextSerParameter(publicKeyParameter.getParameters(), A, B, C);
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new HIBEBBG05HeaderSerParameter(publicKeyParameter.getParameters(), B, C)
        );
    }
}

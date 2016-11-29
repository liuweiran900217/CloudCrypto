package cn.edu.buaa.crypto.encryption.hibe.bbg05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
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
public class HIBEBBG05EncryptionGenerator implements PairingEncryptionGenerator {
    private HIBEEncryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBEEncryptionGenerationParameter)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        HIBEBBG05PublicKeySerParameter publicKeyParameter = (HIBEBBG05PublicKeySerParameter)this.params.getPublicKeyParameter();
        assert(this.params.getLength() <= publicKeyParameter.getMaxLength());
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = pairing.pairing(publicKeyParameter.getG1(), publicKeyParameter.getG2()).powZn(s).getImmutable();
        Element A = sessionKey.mul(this.params.getMessage()).getImmutable();

        Element B = publicKeyParameter.getG().powZn(s).getImmutable();
        Element C = publicKeyParameter.getG3().getImmutable();
        for (int i=0; i<this.params.getLength(); i++){
            C = C.mul(publicKeyParameter.getHsAt(i).powZn(elementIds[i])).getImmutable();
        }
        C = C.powZn(s).getImmutable();
        return new HIBEBBG05CiphertextSerParameter(publicKeyParameter.getParameters(), A, B, C);
    }
}

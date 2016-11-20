package cn.edu.buaa.crypto.encryption.hibe.bbg05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams.HIBEBBG05EncryptionGenerationParameter;
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
    private HIBEBBG05EncryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBEBBG05EncryptionGenerationParameter)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        HIBEBBG05PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2()).powZn(s).getImmutable();
        Element A = sessionKey.mul(this.params.getMessage()).getImmutable();

        Element B = publicKeyParameters.getG().powZn(s).getImmutable();
        Element C = publicKeyParameters.getG3().getImmutable();
        for (int i=0; i<this.params.getLength(); i++){
            C = C.mul(publicKeyParameters.getHsAt(i).powZn(elementIds[i])).getImmutable();
        }
        C = C.powZn(s).getImmutable();
        return new HIBEBBG05CipherSerParameter(publicKeyParameters.getParameters(), A, B, C);
    }
}

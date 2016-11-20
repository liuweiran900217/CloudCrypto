package cn.edu.buaa.crypto.encryption.hibe.bb04.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.genparams.HIBEBB04EncryptionGenerationParameter;
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
public class HIBEBB04EncryptionGenerator implements PairingEncryptionGenerator {

    private HIBEBB04EncryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBEBB04EncryptionGenerationParameter)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        HIBEBB04PublicKeySerParameter publicKeyParameters = (HIBEBB04PublicKeySerParameter)this.params.getPublicKeyParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2()).powZn(s).getImmutable();
        Element A = sessionKey.mul(this.params.getMessage()).getImmutable();

        Element B = publicKeyParameters.getG().powZn(s).getImmutable();
        Element[] Cs = new Element[ids.length];
        for (int i = 0; i < Cs.length; i++){
            Cs[i] = publicKeyParameters.getG1().powZn(elementIds[i]).mul(publicKeyParameters.getHsAt(i)).powZn(s).getImmutable();
        }
        return new HIBEBB04CiphertextSerParameter(publicKeyParameters.getParameters(), A, B, Cs);
    }
}

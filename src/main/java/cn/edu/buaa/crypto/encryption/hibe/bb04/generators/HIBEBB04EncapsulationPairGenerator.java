package cn.edu.buaa.crypto.encryption.hibe.bb04.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.genparams.HIBEBB04CiphertextGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.bb04.serparams.HIBEBB04PublicKeySerParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * Encapsulation key / ciphertext pair generation generator for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04EncapsulationPairGenerator implements PairingEncapsulationPairGenerator {

    private HIBEBB04CiphertextGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBEBB04CiphertextGenerationParameter)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        HIBEBB04PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2()).powZn(s).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();

        Element B = publicKeyParameters.getG().powZn(s).getImmutable();
        Element[] Cs = new Element[ids.length];
        for (int i = 0; i < Cs.length; i++){
            Cs[i] = publicKeyParameters.getG1().powZn(elementIds[i]).mul(publicKeyParameters.getHsAt(i)).powZn(s).getImmutable();
        }
        return new PairingKeyEncapsulationSerPair(
                byteArraySessionKey,
                new HIBEBB04CipherSerParameter(publicKeyParameters.getParameters(), ids.length, B, Cs));
    }
}

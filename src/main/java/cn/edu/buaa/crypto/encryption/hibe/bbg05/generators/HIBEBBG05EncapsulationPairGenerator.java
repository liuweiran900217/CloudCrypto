package cn.edu.buaa.crypto.encryption.hibe.bbg05.generators;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05CiphertextGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.params.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Ciphertext Encapsulation generator for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05EncapsulationPairGenerator implements PairingEncapsulationPairGenerator {
    private HIBEBBG05CiphertextGenerationParameters params;

    public void init(CipherParameters params) {
        this.params = (HIBEBBG05CiphertextGenerationParameters)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        HIBEBBG05PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapToZr(pairing, ids);

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2()).powZn(s).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();

        Element B = publicKeyParameters.getG().powZn(s).getImmutable();
        Element C = publicKeyParameters.getG3().getImmutable();
        for (int i=0; i<this.params.getLength(); i++){
            C = C.mul(publicKeyParameters.getHsAt(i).powZn(elementIds[i])).getImmutable();
        }
        C = C.powZn(s).getImmutable();
        return new PairingKeyEncapsulationSerPair(
                byteArraySessionKey,
                new HIBEBBG05CipherSerParameter(publicKeyParameters.getParameters(), ids.length, B, C));
    }
}

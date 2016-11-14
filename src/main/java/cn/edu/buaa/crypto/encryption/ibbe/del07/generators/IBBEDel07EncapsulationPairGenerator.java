package cn.edu.buaa.crypto.encryption.ibbe.del07.generators;

import cn.edu.buaa.crypto.algebra.algorithms.HornerRule;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibbe.del07.genparams.IBBEDel07CiphertextGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07CipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07PublicKeySerParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * encapsulation key / ciphertext pair generation generator for Delerablée IBBE scheme.
 */
public class IBBEDel07EncapsulationPairGenerator implements PairingEncapsulationPairGenerator {

    private IBBEDel07CiphertextGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (IBBEDel07CiphertextGenerationParameter)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        IBBEDel07PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        if (ids.length > publicKeyParameters.getMaxBroadcastReceiver()) {
            throw new IllegalArgumentException("# of broadcast receiver set " + ids.length +
                    " is greater than the maximal number of receivers " + publicKeyParameters.getMaxBroadcastReceiver());
        }

        Element[] elementIds = PairingUtils.MapToZr(pairing, ids);

        Element k = pairing.getZr().newRandomElement().getImmutable();
        //Computer session key
        Element sessionKey = publicKeyParameters.getV().powZn(k).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();

        //Computer C1
        Element C1 = publicKeyParameters.getW().powZn(k.negate()).getImmutable();

        //Compute C2
        Element C2 = pairing.getG2().newOneElement().getImmutable();
        Element[] allCoefficients = HornerRule.ComputeEfficients(pairing, elementIds);
        for (int i = 0; i < allCoefficients.length; i++) {
            C2 = C2.mul(publicKeyParameters.getHsAt(i).powZn(allCoefficients[i])).getImmutable();
        }
        C2 = C2.powZn(k).getImmutable();

        return new PairingKeyEncapsulationSerPair(
                byteArraySessionKey,
                new IBBEDel07CipherSerParameter(publicKeyParameters.getParameters(), C1, C2));
    }
}

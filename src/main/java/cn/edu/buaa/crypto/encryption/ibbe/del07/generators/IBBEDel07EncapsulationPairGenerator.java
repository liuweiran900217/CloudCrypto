package cn.edu.buaa.crypto.encryption.ibbe.del07.generators;

import cn.edu.buaa.crypto.algebra.algorithms.HornerRule;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibbe.genparams.IBBEEncapsulationGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
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

    private IBBEEncapsulationGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (IBBEEncapsulationGenerationParameter)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        IBBEDel07PublicKeySerParameter publicKeyParameters = (IBBEDel07PublicKeySerParameter)this.params.getPublicKeyParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        if (ids.length > publicKeyParameters.getMaxBroadcastReceiver()) {
            throw new IllegalArgumentException("# of broadcast receiver set " + ids.length +
                    " is greater than the maximal number of receivers " + publicKeyParameters.getMaxBroadcastReceiver());
        }

        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

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
                new IBBEDel07HeaderSerParameter(publicKeyParameters.getParameters(), C1, C2));
    }
}

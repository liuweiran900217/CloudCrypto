package cn.edu.buaa.crypto.encryption.hibbe.llw14.generators;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14CiphertextGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14CiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.params.HIBBELLW14PublicKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generator.PairingKeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW14KeyEncapsulationPairGenerator implements PairingKeyEncapsulationPairGenerator {
    private HIBBELLW14CiphertextGenerationParameters params;

    public void init(CipherParameters params) {
        this.params = (HIBBELLW14CiphertextGenerationParameters)params;
    }

    public PairingKeyEncapsulationPair generateEncryptionPair() {
        HIBBELLW14PublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = Utils.MapToZr(pairing, ids);

        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = publicKeyParameters.getEggAlpha().powZn(beta).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();

        Element C0 = publicKeyParameters.getG().powZn(beta).getImmutable();
        Element C1 = publicKeyParameters.getH().getImmutable();
        for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
            if (ids[i] != null){
                C1 = C1.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
            }
        }
        C1 = C1.powZn(beta).getImmutable();
        return new PairingKeyEncapsulationPair(
                Arrays.copyOf(byteArraySessionKey, byteArraySessionKey.length),
                new HIBBELLW14CiphertextParameters(publicKeyParameters.getParameters(), C0, C1));
    }
}

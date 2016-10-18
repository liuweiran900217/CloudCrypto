package cn.edu.buaa.crypto.encryption.hibbe.llw16a.generators;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.params.HIBBELLW16aCiphertextGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.params.HIBBELLW16aCiphertextParameters;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.params.HIBBELLW16aPublicKeyParameters;
import cn.edu.buaa.crypto.pairingkem.generators.PairingKeyEncapsulationPairGenerator;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyEncapsulationPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE session key encapsulation generator.
 */
public class HIBBELLW16aKeyEncapsulationPairGenerator implements PairingKeyEncapsulationPairGenerator {
    private HIBBELLW16aCiphertextGenerationParameters params;

    public void init(CipherParameters params) {
        this.params = (HIBBELLW16aCiphertextGenerationParameters)params;
    }

    public PairingKeyEncapsulationPair generateEncryptionPair() {
        HIBBELLW16aPublicKeyParameters publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapToZr(pairing, ids);

        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = pairing.pairing(publicKeyParameters.getG1(), publicKeyParameters.getG2()).powZn(beta).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();

        Element C0 = publicKeyParameters.getG().powZn(beta).getImmutable();
        Element C1 = publicKeyParameters.getG3().getImmutable();
        for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
            if (ids[i] != null){
                C1 = C1.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
            }
        }
        C1 = C1.powZn(beta).getImmutable();
        return new PairingKeyEncapsulationPair(
                byteArraySessionKey,
                new HIBBELLW16aCiphertextParameters(publicKeyParameters.getParameters(), C0, C1));
    }
}

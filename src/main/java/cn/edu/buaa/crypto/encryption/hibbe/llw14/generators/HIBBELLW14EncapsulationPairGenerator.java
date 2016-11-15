package cn.edu.buaa.crypto.encryption.hibbe.llw14.generators;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams.HIBBELLW14CiphertextGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu prime-order HIBBE ciphertext / session key encapsulation pair generator.
 */
public class HIBBELLW14EncapsulationPairGenerator implements PairingEncapsulationPairGenerator {
    private HIBBELLW14CiphertextGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBBELLW14CiphertextGenerationParameter)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        HIBBELLW14PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

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
        return new PairingKeyEncapsulationSerPair(
                byteArraySessionKey,
                new HIBBELLW14CipherSerParameter(publicKeyParameters.getParameters(), C0, C1));
    }
}

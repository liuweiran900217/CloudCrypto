package cn.edu.buaa.crypto.encryption.hibbe.llw14.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams.HIBBELLW14EncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu prime-order HIBBE encryption generator.
 */
public class HIBBELLW14EncryptionGenerator implements PairingEncryptionGenerator {
    private HIBBELLW14EncryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBBELLW14EncryptionGenerationParameter)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        HIBBELLW14PublicKeySerParameter publicKeyParameters = (HIBBELLW14PublicKeySerParameter)this.params.getPublicKeyParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element message = this.params.getMessage();
        if (ids.length != publicKeyParameters.getMaxUser()) {
            throw new IllegalArgumentException("Invalid identity vector set length");
        }
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = publicKeyParameters.getEggAlpha().powZn(beta).getImmutable();
        Element C2 = sessionKey.mul(message).getImmutable();

        Element C0 = publicKeyParameters.getG().powZn(beta).getImmutable();
        Element C1 = publicKeyParameters.getH().getImmutable();
        for (int i=0; i<publicKeyParameters.getMaxUser(); i++){
            if (ids[i] != null){
                C1 = C1.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
            }
        }
        C1 = C1.powZn(beta).getImmutable();
        return new HIBBELLW14CiphertextSerParameter(publicKeyParameters.getParameters(), C0, C1, C2);
    }
}

package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE decryption generation parameters.
 */
public class HIBBELLW16aDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private String[] ids;

    public HIBBELLW16aDecryptionGenerationParameter(PairingKeySerParameter publicKeyParameters, PairingKeySerParameter secretKeyParameters,
            String[] ids, PairingCipherSerParameter ciphertextParameters) {
        super(publicKeyParameters, secretKeyParameters, ciphertextParameters);
        assert(ids.length == ((HIBBELLW16aPublicKeySerParameter)publicKeyParameters).getMaxUser());
        this.ids = ids;
    }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

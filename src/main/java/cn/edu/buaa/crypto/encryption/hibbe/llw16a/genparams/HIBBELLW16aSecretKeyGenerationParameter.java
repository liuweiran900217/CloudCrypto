package cn.edu.buaa.crypto.encryption.hibbe.llw16a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams.HIBBELLW16aPublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE secret key generation parameters.
 */
public class HIBBELLW16aSecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String[] ids;

    public HIBBELLW16aSecretKeyGenerationParameter(
            PairingKeySerParameter publicKeyParameters,
            PairingKeySerParameter masterSecretKeyParameters,
            String[] ids) {
        super(publicKeyParameters, masterSecretKeyParameters);
        assert(ids.length == ((HIBBELLW16aPublicKeySerParameter)publicKeyParameters).getMaxUser());
        this.ids = ids;
    }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }
}
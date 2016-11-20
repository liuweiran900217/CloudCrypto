package cn.edu.buaa.crypto.encryption.hibbe.llw14.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14PublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE secret key generation parameter.
 */
public class HIBBELLW14SecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String[] ids;

    public HIBBELLW14SecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
            PairingKeySerParameter masterSecretKeyParameter, String[] ids) {
        super(publicKeyParameter, masterSecretKeyParameter);
        assert(ids.length == ((HIBBELLW14PublicKeySerParameter)publicKeyParameter).getMaxUser());
        this.ids = ids;
    }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }
}

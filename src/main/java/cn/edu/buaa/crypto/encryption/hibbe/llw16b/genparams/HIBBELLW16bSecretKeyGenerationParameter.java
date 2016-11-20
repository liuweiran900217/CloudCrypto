package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE secret key generation parameter.
 */
public class HIBBELLW16bSecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String[] ids;

    public HIBBELLW16bSecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter masterSecretKeyParameter,
                                                   String[] ids) {
        super(publicKeyParameter, masterSecretKeyParameter);
        assert(ids.length == ((HIBBELLW16bPublicKeySerParameter)publicKeyParameter).getMaxUser());
        this.ids = ids;
    }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }
}
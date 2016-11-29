package cn.edu.buaa.crypto.encryption.hibe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * HIBE secret key generation parameter.
 */
public class HIBESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String[] ids;

    public HIBESecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
                                            PairingKeySerParameter masterSecretKeyParameter, String[] ids) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.ids = ids;
    }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }

    public int getLength() {
        return ids.length;
    }
}

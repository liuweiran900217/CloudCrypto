package cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key Generation parameters for Boneh-Boyen-Goh HIBBE.
 */
public class HIBEBBG05SecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String[] ids;

    public HIBEBBG05SecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter,
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

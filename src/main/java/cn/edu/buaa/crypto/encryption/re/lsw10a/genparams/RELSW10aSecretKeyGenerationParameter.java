package cn.edu.buaa.crypto.encryption.re.lsw10a.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Waters revocation encryption secret key generation parameter.
 */
public class RELSW10aSecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String id;

    public RELSW10aSecretKeyGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter masterSecretKeyParameter, String id) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.id = id;
    }

    public String getId() { return this.id; }
}

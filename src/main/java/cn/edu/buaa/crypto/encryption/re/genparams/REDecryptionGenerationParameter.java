package cn.edu.buaa.crypto.encryption.re.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Revocation encryption decryption generation parameter.
 */
public class REDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private String[] ids;
    private ChameleonHasher chameleonHasher;

    public REDecryptionGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            String[] ids, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        //remove repeated ids
        this.ids = PairingUtils.removeDuplicates(ids);
    }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return this.ids; }

    public void setChameleonHasher(ChameleonHasher chameleonHasher) {
        this.chameleonHasher = chameleonHasher;
    }

    public ChameleonHasher getChameleonHasher() { return this.chameleonHasher; }
}

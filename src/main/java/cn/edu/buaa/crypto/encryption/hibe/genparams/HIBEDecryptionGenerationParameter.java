package cn.edu.buaa.crypto.encryption.hibe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 15-10-1.
 *
 * HIBE decryption generation parameter.
 */
public class HIBEDecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private String[] ids;

    public HIBEDecryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
                                             String[] ids, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.ids = ids;
    }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

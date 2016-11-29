package cn.edu.buaa.crypto.encryption.ibbe.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * IBBE decapsulation generation parameter.
 */
public class IBBEDecapsulationGenerationParameter extends PairingDecryptionGenerationParameter {
    private String[] ids;

    public IBBEDecapsulationGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            String[] ids, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.ids = PairingUtils.removeDuplicates(ids);
    }

    public int getNumberOfBroadcastReceiver() { return this.ids.length; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

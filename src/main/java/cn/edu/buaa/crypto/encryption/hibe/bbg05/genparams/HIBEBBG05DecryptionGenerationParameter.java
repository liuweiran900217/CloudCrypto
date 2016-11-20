package cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE decryption generation parameter.
 */
public class HIBEBBG05DecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private String[] ids;

    public HIBEBBG05DecryptionGenerationParameter(
            PairingKeySerParameter publicKeyParameters, PairingKeySerParameter secretKeyParameters,
            String[] ids, PairingCipherSerParameter ciphertextParameters) {
        super(publicKeyParameters, secretKeyParameters, ciphertextParameters);
        this.ids = ids;
    }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

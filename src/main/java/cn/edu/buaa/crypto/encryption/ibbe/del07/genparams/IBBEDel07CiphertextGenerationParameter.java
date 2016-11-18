package cn.edu.buaa.crypto.encryption.ibbe.del07.genparams;

import cn.edu.buaa.crypto.encryption.ibbe.del07.serparams.IBBEDel07PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Ciphertext generation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07CiphertextGenerationParameter implements CipherParameters {
    private IBBEDel07PublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public IBBEDel07CiphertextGenerationParameter(CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (IBBEDel07PublicKeySerParameter)publicKeyParameters;
        assert(ids.length <= this.publicKeyParameters.getMaxBroadcastReceiver());
        this.ids = PairingUtils.removeDuplicates(ids);
    }

    public IBBEDel07PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

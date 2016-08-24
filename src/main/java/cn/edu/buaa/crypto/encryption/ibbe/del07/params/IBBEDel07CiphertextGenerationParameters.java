package cn.edu.buaa.crypto.encryption.ibbe.del07.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Ciphertext generation parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07CiphertextGenerationParameters  implements CipherParameters {
    private IBBEDel07PublicKeyParameters publicKeyParameters;
    private String[] ids;

    public IBBEDel07CiphertextGenerationParameters(CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (IBBEDel07PublicKeyParameters)publicKeyParameters;
        assert(ids.length <= this.publicKeyParameters.getMaxBroadcastReceiver());
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public IBBEDel07PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

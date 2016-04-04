package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class RELSW10aCiphertextGenerationParameters implements CipherParameters {
    private RELSW10aPublicKeyParameters publicKeyParameters;
    private String[] ids;

    public RELSW10aCiphertextGenerationParameters(CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (RELSW10aPublicKeyParameters)publicKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public RELSW10aPublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Waters revocation encryption ciphertext generation parameter.
 */
public class RELSW10aCiphertextGenerationParameters implements CipherParameters {
    private RELSW10APublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public RELSW10aCiphertextGenerationParameters(CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (RELSW10APublicKeySerParameter)publicKeyParameters;
        this.ids = ids;
    }

    public RELSW10APublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

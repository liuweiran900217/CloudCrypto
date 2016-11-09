package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Ciphertext Generation parameters for Boneh-Boyen-Goh HIBE.
 */
public class HIBEBBG05CiphertextGenerationParameters implements CipherParameters {
    private HIBEBBG05PublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBEBBG05CiphertextGenerationParameters(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBEBBG05PublicKeySerParameter)publicKeyParameters;
        assert(ids.length <= this.publicKeyParameters.getMaxLength());
        this.ids = ids;
    }

    public HIBEBBG05PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

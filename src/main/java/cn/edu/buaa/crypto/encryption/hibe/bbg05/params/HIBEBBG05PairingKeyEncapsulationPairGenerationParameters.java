package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import org.bouncycastle.crypto.CipherParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/11/3.
 */
public class HIBEBBG05PairingKeyEncapsulationPairGenerationParameters implements CipherParameters {
    private HIBEBBG05PublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBEBBG05PairingKeyEncapsulationPairGenerationParameters(
            CipherParameters publicKeyParameters, String[] ids) {
        this.publicKeyParameters = (HIBEBBG05PublicKeyParameters)publicKeyParameters;
        assert(ids.length <= this.publicKeyParameters.getMaxLength());
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public HIBEBBG05PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return Arrays.copyOf(ids, ids.length); }

    public String getIdAt(int index) { return ids[index]; }

    public int getLength() { return this.ids.length; }
}

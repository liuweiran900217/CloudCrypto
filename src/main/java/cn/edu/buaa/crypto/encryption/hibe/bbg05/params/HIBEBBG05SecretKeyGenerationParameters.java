package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key Generation parameters for Boneh-Boyen-Goh HIBBE.
 */
public class HIBEBBG05SecretKeyGenerationParameters extends KeyGenerationParameters {
    private HIBEBBG05MasterSecretKeyParameters masterSecretKeyParameters;
    private HIBEBBG05PublicKeyParameters publicKeyParameters;
    private String[] ids;

    public HIBEBBG05SecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, PairingUtils.STENGTH);
        this.masterSecretKeyParameters = (HIBEBBG05MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBEBBG05PublicKeyParameters)publicKeyParameters;
        this.ids = Arrays.copyOf(ids, ids.length);
    }

    public HIBEBBG05MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBEBBG05PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return Arrays.copyOf(ids, ids.length);
    }

    public int getLength() {
        return ids.length;
    }
}

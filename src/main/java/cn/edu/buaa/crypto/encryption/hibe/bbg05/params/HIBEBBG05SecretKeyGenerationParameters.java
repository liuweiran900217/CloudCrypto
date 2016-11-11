package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key Generation parameters for Boneh-Boyen-Goh HIBBE.
 */
public class HIBEBBG05SecretKeyGenerationParameters extends KeyGenerationParameters {
    private HIBEBBG05MasterSecretKeySerParameter masterSecretKeyParameters;
    private HIBEBBG05PublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBEBBG05SecretKeyGenerationParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.masterSecretKeyParameters = (HIBEBBG05MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBEBBG05PublicKeySerParameter)publicKeyParameters;
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, this.ids.length);
    }

    public HIBEBBG05MasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public HIBEBBG05PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getIdAt(int index) {
        return ids[index];
    }

    public String[] getIds() {
        return this.ids;
    }

    public int getLength() {
        return ids.length;
    }
}

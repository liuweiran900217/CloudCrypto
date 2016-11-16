package cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams;

import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Secret Key Generation parameters for Boneh-Boyen-Goh HIBBE.
 */
public class HIBEBBG05SecretKeyGenerationParameter extends KeyGenerationParameters {
    private HIBEBBG05MasterSecretKeySerParameter masterSecretKeyParameters;
    private HIBEBBG05PublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBEBBG05SecretKeyGenerationParameter(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String[] ids) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.masterSecretKeyParameters = (HIBEBBG05MasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (HIBEBBG05PublicKeySerParameter)publicKeyParameters;
        this.ids = ids;
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

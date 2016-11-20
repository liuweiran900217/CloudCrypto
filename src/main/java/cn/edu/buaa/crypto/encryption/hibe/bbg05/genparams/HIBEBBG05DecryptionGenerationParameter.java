package cn.edu.buaa.crypto.encryption.hibe.bbg05.genparams;

import cn.edu.buaa.crypto.encryption.hibe.bbg05.HIBEBBG05Engine;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams.HIBEBBG05SecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE decryption generation parameter.
 */
public class HIBEBBG05DecryptionGenerationParameter implements CipherParameters {
    private HIBEBBG05PublicKeySerParameter publicKeyParameters;
    private HIBEBBG05SecretKeySerParameter secretKeyParameters;
    private String[] ids;
    private HIBEBBG05CipherSerParameter ciphertextParameters;

    public HIBEBBG05DecryptionGenerationParameter(CipherParameters publicKeyParameters, CipherParameters secretKeyParameters,
            String[] ids, CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (HIBEBBG05PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (HIBEBBG05SecretKeySerParameter)secretKeyParameters;
        this.ids = ids;
        this.ciphertextParameters = (HIBEBBG05CipherSerParameter)ciphertextParameters;
    }

    public HIBEBBG05PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public HIBEBBG05SecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public HIBEBBG05CipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int getLength() { return this.ids.length; }

    public String[] getIds() { return this.ids; }

    public String getIdsAt(int index) { return this.ids[index]; }
}

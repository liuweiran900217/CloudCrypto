package cn.edu.buaa.crypto.encryption.ibe.lw10.genparams;

import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10CipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10SecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by liuweiran on 16/5/7.
 *
 * Lewko-Waters IBE decryption generation parameter.
 */
public class IBELW10DecryptionGenerationParameter implements CipherParameters {
    private IBELW10PublicKeySerParameter publicKeyParameters;
    private IBELW10SecretKeySerParameter secretKeyParameters;
    private String id;
    private IBELW10CipherSerParameter ciphertextParameters;

    public IBELW10DecryptionGenerationParameter(
            CipherParameters publicKeyParameters, CipherParameters secretKeyParameters,
            String id, CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (IBELW10PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (IBELW10SecretKeySerParameter)secretKeyParameters;
        this.id = id;
        this.ciphertextParameters = (IBELW10CipherSerParameter)ciphertextParameters;
    }

    public IBELW10PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public IBELW10SecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public IBELW10CipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String getId() { return this.id; }
}

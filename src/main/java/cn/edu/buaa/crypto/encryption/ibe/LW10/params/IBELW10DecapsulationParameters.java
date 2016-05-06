package cn.edu.buaa.crypto.encryption.ibe.LW10.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by liuweiran on 16/5/7.
 */
public class IBELW10DecapsulationParameters implements CipherParameters {
    private IBELW10PublicKeyParameters publicKeyParameters;
    private IBELW10SecretKeyParameters secretKeyParameters;
    private String id;
    private IBELW10CiphertextParameters ciphertextParameters;

    public IBELW10DecapsulationParameters(
            CipherParameters publicKeyParameters, CipherParameters secretKeyParameters,
            String id, CipherParameters ciphertextParameters) {
        this.publicKeyParameters = (IBELW10PublicKeyParameters)publicKeyParameters;
        this.secretKeyParameters = (IBELW10SecretKeyParameters)secretKeyParameters;
        this.id = id;
        this.ciphertextParameters = (IBELW10CiphertextParameters)ciphertextParameters;
    }

    public IBELW10PublicKeyParameters getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public IBELW10SecretKeyParameters getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public IBELW10CiphertextParameters getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public String getId() { return this.id; }
}

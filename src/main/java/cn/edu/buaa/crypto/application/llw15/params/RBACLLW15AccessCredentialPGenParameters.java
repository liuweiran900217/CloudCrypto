package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.application.llw15.RBACLLW15Engine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/19.
 */
public class RBACLLW15AccessCredentialPGenParameters extends KeyGenerationParameters {
    private RBACLLW15MasterSecretKeyParameters masterSecretKeyParameters;
    private RBACLLW15PublicKeyParameters publicKeyParameters;
    private String id;

    public RBACLLW15AccessCredentialPGenParameters(
            CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters,
            String id) {
        super(null, RBACLLW15Engine.STENGTH);
        this.masterSecretKeyParameters = (RBACLLW15MasterSecretKeyParameters)masterSecretKeyParameters;
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
        this.id = new String(id);
    }

    public RBACLLW15MasterSecretKeyParameters getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public RBACLLW15PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }

    public String getId() { return id; }

}

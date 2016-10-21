package cn.edu.buaa.crypto.application.llw15.params;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/10/8.
 *
 * Liu-Liu-Wu role-based access control intermediate generation parameters.
 */
public class RBACLLW15IntermediateGenParameters implements CipherParameters {
    private RBACLLW15PublicKeyParameters publicKeyParameters;

    public RBACLLW15IntermediateGenParameters(CipherParameters publicKeyParameters) {
        this.publicKeyParameters = (RBACLLW15PublicKeyParameters)publicKeyParameters;
    }

    public RBACLLW15PublicKeyParameters getPublicKeyParameters() { return this.publicKeyParameters; }
}

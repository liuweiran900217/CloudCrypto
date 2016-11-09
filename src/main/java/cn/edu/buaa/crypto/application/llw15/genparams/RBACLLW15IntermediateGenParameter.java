package cn.edu.buaa.crypto.application.llw15.genparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.application.llw15.serparams.RBACLLW15PublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/10/8.
 *
 * Liu-Liu-Wu role-based access control intermediate generation parameters.
 */
public class RBACLLW15IntermediateGenParameter implements CipherParameters {
    private RBACLLW15PublicKeySerParameter publicKeyParameters;

    public RBACLLW15IntermediateGenParameter(AsymmetricKeySerParameter publicKeyParameters) {
        this.publicKeyParameters = (RBACLLW15PublicKeySerParameter)publicKeyParameters;
    }

    public RBACLLW15PublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }
}

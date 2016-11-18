package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE secret key generation parameter.
 */
public class KPABEGPSW06aSecretKeyGenerationParameter extends KeyGenerationParameters {

    private KPABEGPSW06aMasterSecretKeySerParameter masterSecretKeyParameters;
    private KPABEGPSW06aPublicKeySerParameter publicKeyParameters;
    private AccessControlEngine accessControlEngine;
    private int[][] accessPolicy;
    private String[] rhos;

    public KPABEGPSW06aSecretKeyGenerationParameter(
            AccessControlEngine accessControlEngines, CipherParameters publicKeyParameters,
            CipherParameters masterSecretKeyParameters, int[][] accessPolicy, String[] rhos) {
        super(null, PairingParametersGenerationParameter.STENGTH);
        this.masterSecretKeyParameters = (KPABEGPSW06aMasterSecretKeySerParameter)masterSecretKeyParameters;
        this.publicKeyParameters = (KPABEGPSW06aPublicKeySerParameter)publicKeyParameters;
        this.accessControlEngine = accessControlEngines;

        assert(rhos.length <= this.publicKeyParameters.getMaxAttributesNum());
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }

    public KPABEGPSW06aMasterSecretKeySerParameter getMasterSecretKeyParameters() { return this.masterSecretKeyParameters; }

    public KPABEGPSW06aPublicKeySerParameter getPublicKeyParameters() { return this.publicKeyParameters; }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

    public String[] getRhos() { return this.rhos; }
}


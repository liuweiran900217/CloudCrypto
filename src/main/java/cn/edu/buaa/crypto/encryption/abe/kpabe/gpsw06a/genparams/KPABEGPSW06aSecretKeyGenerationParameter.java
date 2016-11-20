package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams.KPABEGPSW06aPublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE secret key generation parameter.
 */
public class KPABEGPSW06aSecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private AccessControlEngine accessControlEngine;
    private int[][] accessPolicy;
    private String[] rhos;

    public KPABEGPSW06aSecretKeyGenerationParameter(
            AccessControlEngine accessControlEngines, PairingKeySerParameter publicKeyParameter,
            PairingKeySerParameter masterSecretKeyParameter, int[][] accessPolicy, String[] rhos) {
        super(publicKeyParameter, masterSecretKeyParameter);
        assert(rhos.length <= ((KPABEGPSW06aPublicKeySerParameter)publicKeyParameter).getMaxAttributesNum());
        this.accessControlEngine = accessControlEngines;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

    public String[] getRhos() { return this.rhos; }
}


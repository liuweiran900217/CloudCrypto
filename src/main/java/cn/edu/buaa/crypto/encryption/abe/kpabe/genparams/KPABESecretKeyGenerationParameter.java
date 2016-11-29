package cn.edu.buaa.crypto.encryption.abe.kpabe.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * KP-ABE secret key generation parameter.
 */
public class KPABESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private AccessControlEngine accessControlEngine;
    private int[][] accessPolicy;
    private String[] rhos;

    public KPABESecretKeyGenerationParameter(
            AccessControlEngine accessControlEngines, PairingKeySerParameter publicKeyParameter,
            PairingKeySerParameter masterSecretKeyParameter, int[][] accessPolicy, String[] rhos) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.accessControlEngine = accessControlEngines;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

    public String[] getRhos() { return this.rhos; }
}


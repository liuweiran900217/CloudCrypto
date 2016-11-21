package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles secret key generation parameter.
 */
public class KPABEGPSW06bSecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private AccessControlEngine accessControlEngine;
    private int[][] accessPolicy;
    private String[] rhos;

    public KPABEGPSW06bSecretKeyGenerationParameter(
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

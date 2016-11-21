package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingDecryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;

/**
 * Created by Administrator on 2016/11/20.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE session key decapsulation parameter.
 */
public class CPABEBSW07DecryptionGenerationParameter extends PairingDecryptionGenerationParameter {
    private int[][] accessPolicy;
    private String[] rhos;
    private AccessControlEngine accessControlEngine;

    public CPABEBSW07DecryptionGenerationParameter(
            AccessControlEngine accessControlEngine, PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            int[][] accessPolicy, String[] rhos, PairingCipherSerParameter ciphertextParameter) {
        super(publicKeyParameter, secretKeyParameter, ciphertextParameter);
        this.accessControlEngine = accessControlEngine;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

    public String[] getRhos() { return this.rhos; }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }
}

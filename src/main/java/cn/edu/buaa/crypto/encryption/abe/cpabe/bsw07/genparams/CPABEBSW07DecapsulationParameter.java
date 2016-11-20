package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07CipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07SecretKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Administrator on 2016/11/20.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE session key decapsulation parameter.
 */
public class CPABEBSW07DecapsulationParameter implements CipherParameters {
    private CPABEBSW07PublicKeySerParameter publicKeyParameters;
    private CPABEBSW07SecretKeySerParameter secretKeyParameters;
    private int[][] accessPolicy;
    private String[] rhos;
    private CPABEBSW07CipherSerParameter ciphertextParameters;
    private AccessControlEngine accessControlEngine;

    public CPABEBSW07DecapsulationParameter(
            AccessControlEngine accessControlEngine, CipherParameters publicKeyParameters, CipherParameters secretKeyParameters,
            int[][] accessPolicy, String[] rhos, CipherParameters ciphertextParameters) {
        this.accessControlEngine = accessControlEngine;
        this.publicKeyParameters = (CPABEBSW07PublicKeySerParameter)publicKeyParameters;
        this.secretKeyParameters = (CPABEBSW07SecretKeySerParameter)secretKeyParameters;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
        this.ciphertextParameters = (CPABEBSW07CipherSerParameter)ciphertextParameters;
    }

    public CPABEBSW07PublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public CPABEBSW07SecretKeySerParameter getSecretKeyParameters() {
        return this.secretKeyParameters;
    }

    public CPABEBSW07CipherSerParameter getCiphertextParameters() {
        return this.ciphertextParameters;
    }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

    public String[] getRhos() { return this.rhos; }

    public AccessControlEngine getAccessControlEngine() { return this.accessControlEngine; }
}

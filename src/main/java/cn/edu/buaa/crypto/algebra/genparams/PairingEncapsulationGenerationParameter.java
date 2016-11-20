package cn.edu.buaa.crypto.algebra.genparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Administrator on 2016/11/20.
 *
 * Pairing key encapsulation generation parameter.
 */
public abstract class PairingEncapsulationGenerationParameter implements CipherParameters {
    private AsymmetricKeySerParameter publicKeyParameter;

    public PairingEncapsulationGenerationParameter(AsymmetricKeySerParameter publicKeyParameter) {
        this.publicKeyParameter = publicKeyParameter;
    }

    public AsymmetricKeySerParameter getPublicKeyParameter() { return this.publicKeyParameter; }
}

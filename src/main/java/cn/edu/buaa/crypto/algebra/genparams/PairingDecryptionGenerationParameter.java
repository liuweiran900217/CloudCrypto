package cn.edu.buaa.crypto.algebra.genparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * Pairing decryption generation parameter
 */
public abstract class PairingDecryptionGenerationParameter implements CipherParameters {
    private AsymmetricKeySerParameter publicKeyParameter;
    private AsymmetricKeySerParameter secretKeyParameter;
    private PairingCipherSerParameter ciphertextParameter;

    public PairingDecryptionGenerationParameter(
            AsymmetricKeySerParameter publicKeyParameter, AsymmetricKeySerParameter secretKeyParameter,
            PairingCipherSerParameter ciphertextParameter) {
        this.publicKeyParameter = publicKeyParameter;
        this.secretKeyParameter = secretKeyParameter;
        this.ciphertextParameter = ciphertextParameter;
    }
    public AsymmetricKeySerParameter getPublicKeyParameter() { return this.publicKeyParameter; }

    public AsymmetricKeySerParameter getSecretKeyParameter() { return this.secretKeyParameter; }

    public PairingCipherSerParameter getCiphertextParameter() { return this.ciphertextParameter; }
}

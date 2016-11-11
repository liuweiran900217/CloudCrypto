package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Signer;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE ciphertext generation parameter.
 */
public class HIBBELLW16bCiphertextGenerationParameter implements CipherParameters {
    private Signer signer;
    AsymmetricKeySerPairGenerator signKeyPairGenerator;
    private KeyGenerationParameters signKeyGenerationParameter;
    private HIBBELLW16bPublicKeySerParameter publicKeyParameters;
    private String[] ids;

    public HIBBELLW16bCiphertextGenerationParameter(Signer signer, AsymmetricKeySerPairGenerator signKeyPairGenerator,
        KeyGenerationParameters keyGenerationParameters, CipherParameters publicKeyParameters, String[] ids) {
        this.signer = signer;
        this.signKeyPairGenerator = signKeyPairGenerator;
        this.signKeyGenerationParameter = keyGenerationParameters;
        this.publicKeyParameters = (HIBBELLW16bPublicKeySerParameter)publicKeyParameters;
        assert(ids.length == this.publicKeyParameters.getMaxUser());
        this.ids = new String[ids.length];
        System.arraycopy(ids, 0, this.ids, 0, ids.length);
    }

    public HIBBELLW16bPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public AsymmetricKeySerPairGenerator getSignKeyPairGenerator() { return this.signKeyPairGenerator; }

    public KeyGenerationParameters getSignKeyGenerationParameters() { return this.signKeyGenerationParameter; }

    public Signer getSigner() { return this.signer; }
}

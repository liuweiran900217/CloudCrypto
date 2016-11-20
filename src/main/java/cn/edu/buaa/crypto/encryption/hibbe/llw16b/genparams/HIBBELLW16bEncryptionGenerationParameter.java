package cn.edu.buaa.crypto.encryption.hibbe.llw16b.genparams;

import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.Signer;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE encryption generation parameter.
 */
public class HIBBELLW16bEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private Signer signer;
    private PairingKeyPairGenerator signKeyPairGenerator;
    private KeyGenerationParameters signKeyGenerationParameter;
    private String[] ids;

    public HIBBELLW16bEncryptionGenerationParameter(
            Signer signer, PairingKeyPairGenerator signKeyPairGenerator, KeyGenerationParameters keyGenerationParameters,
            PairingKeySerParameter publicKeyParameter, String[] ids, Element message) {
        super(publicKeyParameter, message);
        assert(ids.length == ((HIBBELLW16bPublicKeySerParameter)publicKeyParameter).getMaxUser());
        this.signer = signer;
        this.signKeyPairGenerator = signKeyPairGenerator;
        this.signKeyGenerationParameter = keyGenerationParameters;
        this.ids = ids;
    }

    public String[] getIds() { return this.ids; }

    public String getIdAt(int index) { return ids[index]; }

    public PairingKeyPairGenerator getSignKeyPairGenerator() { return this.signKeyPairGenerator; }

    public KeyGenerationParameters getSignKeyGenerationParameters() { return this.signKeyGenerationParameter; }

    public Signer getSigner() { return this.signer; }
}

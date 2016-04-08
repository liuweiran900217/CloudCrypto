package cn.edu.buaa.crypto.chameleonhash.params;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

/**
 * Created by Weiran Liu on 2016/4/8.
 */
public class ChameleonHashAsymmetricCipherKeyPair extends AsymmetricCipherKeyPair {
    public ChameleonHashAsymmetricCipherKeyPair(ChameleonHashPublicKeyParameters publicParam, ChameleonHashSecretKeyParameters privateParam) {
        super(publicParam, privateParam);
    }

    public ChameleonHashPublicKeyParameters getPublic() {
        return (ChameleonHashPublicKeyParameters) super.getPublic();
    }

    public ChameleonHashSecretKeyParameters getPrivate() {
        return (ChameleonHashSecretKeyParameters) super.getPrivate();
    }
}

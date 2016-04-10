package cn.edu.buaa.crypto.encryption.re.oolsw10a.generators;

import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aPublicKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aKeyPairGenerationParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aMasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aPublicKeyParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class OORELSW10aKeyPairGenerator extends RELSW10aKeyPairGenerator {
    private CHEngine chEngine;

    @Override
    public void init(KeyGenerationParameters param) {
        super.init(param);
        OORELSW10aKeyPairGenerationParameters keyPairGenerationParameters = (OORELSW10aKeyPairGenerationParameters)param;
        this.chEngine = keyPairGenerationParameters.getCHEngine();
    }
    @Override
    public AsymmetricCipherKeyPair generateKeyPair() {
        AsymmetricCipherKeyPair keyPair = super.generateKeyPair();
        RELSW10aPublicKeyParameters publicKeyParameters = (RELSW10aPublicKeyParameters)keyPair.getPublic();
        RELSW10aMasterSecretKeyParameters masterSecretKeyParameters = (RELSW10aMasterSecretKeyParameters)keyPair.getPrivate();
        return new AsymmetricCipherKeyPair(
                new OORELSW10aPublicKeyParameters(this.chEngine, publicKeyParameters),
                new OORELSW10aMasterSecretKeyParameters(masterSecretKeyParameters));
    }
}

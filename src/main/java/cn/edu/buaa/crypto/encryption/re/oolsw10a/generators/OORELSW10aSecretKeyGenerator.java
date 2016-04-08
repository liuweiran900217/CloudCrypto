package cn.edu.buaa.crypto.encryption.re.oolsw10a.generators;

import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.params.RELSW10aSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.re.oolsw10a.params.OORELSW10aSecretKeyParameters;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/4/7.
 */
public class OORELSW10aSecretKeyGenerator extends RELSW10aSecretKeyGenerator {

    @Override
    public CipherParameters generateKey() {
        RELSW10aSecretKeyParameters secretKey = (RELSW10aSecretKeyParameters) super.generateKey();
        return new OORELSW10aSecretKeyParameters(secretKey);
    }
}

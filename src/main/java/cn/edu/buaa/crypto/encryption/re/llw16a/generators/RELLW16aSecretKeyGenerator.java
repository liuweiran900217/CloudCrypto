package cn.edu.buaa.crypto.encryption.re.llw16a.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aSecretKeySerParameter;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CPA-secure RE secret key generator.
 */
public class RELLW16aSecretKeyGenerator extends RELSW10aSecretKeyGenerator {
    public PairingKeySerParameter generateKey() {
        RELSW10aSecretKeySerParameter oriSecretKeyParameter = (RELSW10aSecretKeySerParameter) super.generateKey();
        return new RELLW16aSecretKeySerParameter(
                oriSecretKeyParameter.getParameters(),
                oriSecretKeyParameter.getId(),
                oriSecretKeyParameter.getElementId(),
                oriSecretKeyParameter.getD0(),
                oriSecretKeyParameter.getD1(),
                oriSecretKeyParameter.getD2()
        );
    }
}

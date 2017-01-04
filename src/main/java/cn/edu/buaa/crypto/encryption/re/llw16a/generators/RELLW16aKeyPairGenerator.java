package cn.edu.buaa.crypto.encryption.re.llw16a.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aPublicKeySerParameter;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CPA-secure RE public key / master secret key generator.
 */
public class RELLW16aKeyPairGenerator extends RELSW10aKeyPairGenerator {
    public PairingKeySerPair generateKeyPair() {
        PairingKeySerPair keyPair = super.generateKeyPair();
        RELSW10aPublicKeySerParameter oriPublicKeyParameter = (RELSW10aPublicKeySerParameter) keyPair.getPublic();
        RELSW10aMasterSecretKeySerParameter oriMasterSecretKeyParameter = (RELSW10aMasterSecretKeySerParameter) keyPair.getPrivate();
        RELLW16aPublicKeySerParameter publicKeyParameter = new RELLW16aPublicKeySerParameter(
                oriPublicKeyParameter.getParameters(),
                oriPublicKeyParameter.getG(),
                oriPublicKeyParameter.getGb(),
                oriPublicKeyParameter.getGb2(),
                oriPublicKeyParameter.getHb(),
                oriPublicKeyParameter.getEggAlpha()
        );
        RELLW16aMasterSecretKeySerParameter masterSecretKeyParameter = new RELLW16aMasterSecretKeySerParameter(
                oriMasterSecretKeyParameter.getParameters(),
                oriMasterSecretKeyParameter.getAlpha(),
                oriMasterSecretKeyParameter.getB(),
                oriMasterSecretKeyParameter.getH()
        );
        return new PairingKeySerPair(publicKeyParameter, masterSecretKeyParameter);
    }
}
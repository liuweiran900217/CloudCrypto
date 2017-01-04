package cn.edu.buaa.crypto.encryption.re.llw16b.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.re.llw16a.generators.RELLW16aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bPublicKeySerParameter;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE public key / master secret key pair generator.
 */
public class RELLW16bKeyPairGenerator extends RELLW16aKeyPairGenerator {
    public PairingKeySerPair generateKeyPair() {
        PairingKeySerPair pairingKeySerPair = super.generateKeyPair();
        RELLW16aPublicKeySerParameter oriPublicKeyParameter = (RELLW16aPublicKeySerParameter) pairingKeySerPair.getPublic();
        RELLW16aMasterSecretKeySerParameter oriMasterKeyParameter = (RELLW16aMasterSecretKeySerParameter) pairingKeySerPair.getPrivate();

        RELLW16bPublicKeySerParameter publicKeyParameter = new RELLW16bPublicKeySerParameter(
                oriPublicKeyParameter.getParameters(),
                oriPublicKeyParameter.getG(),
                oriPublicKeyParameter.getGb(),
                oriPublicKeyParameter.getGb2(),
                oriPublicKeyParameter.getHb(),
                oriPublicKeyParameter.getEggAlpha()
        );
        RELLW16bMasterSecretKeySerParameter masterKeyParameter = new RELLW16bMasterSecretKeySerParameter(
                oriMasterKeyParameter.getParameters(),
                oriMasterKeyParameter.getAlpha(),
                oriMasterKeyParameter.getB(),
                oriMasterKeyParameter.getH()
        );
        return new PairingKeySerPair(publicKeyParameter, masterKeyParameter);
    }
}

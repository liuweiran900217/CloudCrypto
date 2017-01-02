package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13PublicKeySerParameter;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE public key / master secret key pair generator.
 */
public class KPABEHW14KeyPairGenerator extends KPABERW13KeyPairGenerator {
    public PairingKeySerPair generateKeyPair(){
        PairingKeySerPair keyPair = super.generateKeyPair();
        KPABERW13PublicKeySerParameter oriPublicKeyParameter = (KPABERW13PublicKeySerParameter) keyPair.getPublic();
        KPABERW13MasterSecretKeySerParameter oriMasterSecretKeyParameter = (KPABERW13MasterSecretKeySerParameter) keyPair.getPrivate();
        KPABEHW14PublicKeySerParameter publicKeyParameter = new KPABEHW14PublicKeySerParameter(
                oriPublicKeyParameter.getParameters(),
                oriPublicKeyParameter.getG(),
                oriPublicKeyParameter.getU(),
                oriPublicKeyParameter.getH(),
                oriPublicKeyParameter.getW(),
                oriPublicKeyParameter.getEggAlpha()
        );
        KPABEHW14MasterSecretKeySerParameter masterSecretKeyParameter = new KPABEHW14MasterSecretKeySerParameter(
                oriMasterSecretKeyParameter.getParameters(),
                oriMasterSecretKeyParameter.getAlpha()
        );
        return new PairingKeySerPair(publicKeyParameter, masterSecretKeyParameter);
    }
}

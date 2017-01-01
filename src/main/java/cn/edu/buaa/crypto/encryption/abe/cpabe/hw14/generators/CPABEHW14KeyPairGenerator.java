package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE public key / master secret key pair generator.
 */
public class CPABEHW14KeyPairGenerator extends CPABERW13KeyPairGenerator {
    public PairingKeySerPair generateKeyPair(){
        PairingKeySerPair keyPair = super.generateKeyPair();
        CPABERW13PublicKeySerParameter oriPublicKeyParameter = (CPABERW13PublicKeySerParameter) keyPair.getPublic();
        CPABERW13MasterSecretKeySerParameter oriMasterSecretKeyParameter = (CPABERW13MasterSecretKeySerParameter) keyPair.getPrivate();
        CPABEHW14PublicKeySerParameter publicKeyParameter = new CPABEHW14PublicKeySerParameter(
                oriPublicKeyParameter.getParameters(),
                oriPublicKeyParameter.getG(),
                oriPublicKeyParameter.getU(),
                oriPublicKeyParameter.getH(),
                oriPublicKeyParameter.getW(),
                oriPublicKeyParameter.getV(),
                oriPublicKeyParameter.getEggAlpha()
        );
        CPABEHW14MasterSecretKeySerParameter masterSecretKeyParameter = new CPABEHW14MasterSecretKeySerParameter(
                oriMasterSecretKeyParameter.getParameters(),
                oriMasterSecretKeyParameter.getAlpha()
        );
        return new PairingKeySerPair(publicKeyParameter, masterSecretKeyParameter);
    }
}

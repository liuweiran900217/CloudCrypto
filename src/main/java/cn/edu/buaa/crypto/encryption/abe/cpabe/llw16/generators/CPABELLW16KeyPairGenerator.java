package cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators.CPABEHW14KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams.CPABELLW16PublicKeySerParameter;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-CP-ABE public key / master secret key pair generator.
 */
public class CPABELLW16KeyPairGenerator extends CPABEHW14KeyPairGenerator {
    public PairingKeySerPair generateKeyPair() {
        PairingKeySerPair pairingKeySerPair = super.generateKeyPair();
        CPABEHW14PublicKeySerParameter publicKeyRW13Parameter = (CPABEHW14PublicKeySerParameter) pairingKeySerPair.getPublic();
        CPABEHW14MasterSecretKeySerParameter masterKeyRW13Parameter = (CPABEHW14MasterSecretKeySerParameter) pairingKeySerPair.getPrivate();

        CPABELLW16PublicKeySerParameter publicKeyParameter = new CPABELLW16PublicKeySerParameter(
                publicKeyRW13Parameter.getParameters(),
                publicKeyRW13Parameter.getG(),
                publicKeyRW13Parameter.getU(),
                publicKeyRW13Parameter.getH(),
                publicKeyRW13Parameter.getW(),
                publicKeyRW13Parameter.getV(),
                publicKeyRW13Parameter.getF(),
                publicKeyRW13Parameter.getEggAlpha()
        );
        CPABELLW16MasterSecretKeySerParameter masterKeyParameter = new CPABELLW16MasterSecretKeySerParameter(
                masterKeyRW13Parameter.getParameters(),
                masterKeyRW13Parameter.getAlpha()
        );
        return new PairingKeySerPair(publicKeyParameter, masterKeyParameter);
    }
}

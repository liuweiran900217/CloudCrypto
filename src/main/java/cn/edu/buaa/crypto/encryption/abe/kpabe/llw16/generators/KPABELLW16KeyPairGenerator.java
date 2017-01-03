package cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators.KPABEHW14KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.KPABELLW16MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.KPABELLW16PublicKeySerParameter;

/**
 * Created by Weiran Liu on 2017/1/3.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-KP-ABE public key / master secret key pair generator.
 */
public class KPABELLW16KeyPairGenerator extends KPABEHW14KeyPairGenerator {
    public PairingKeySerPair generateKeyPair() {
        PairingKeySerPair pairingKeySerPair = super.generateKeyPair();
        KPABEHW14PublicKeySerParameter publicKeyRW13Parameter = (KPABEHW14PublicKeySerParameter) pairingKeySerPair.getPublic();
        KPABEHW14MasterSecretKeySerParameter masterKeyRW13Parameter = (KPABEHW14MasterSecretKeySerParameter) pairingKeySerPair.getPrivate();

        KPABELLW16PublicKeySerParameter publicKeyParameter = new KPABELLW16PublicKeySerParameter(
                publicKeyRW13Parameter.getParameters(),
                publicKeyRW13Parameter.getG(),
                publicKeyRW13Parameter.getU(),
                publicKeyRW13Parameter.getH(),
                publicKeyRW13Parameter.getW(),
                publicKeyRW13Parameter.getEggAlpha()
        );
        KPABELLW16MasterSecretKeySerParameter masterKeyParameter = new KPABELLW16MasterSecretKeySerParameter(
                masterKeyRW13Parameter.getParameters(),
                masterKeyRW13Parameter.getAlpha()
        );
        return new PairingKeySerPair(publicKeyParameter, masterKeyParameter);
    }
}

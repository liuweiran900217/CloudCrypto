package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13SecretKeySerParameter;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE secret key generator.
 */
public class KPABEHW14SecretKeyGenerator extends KPABERW13SecretKeyGenerator {
    public PairingKeySerParameter generateKey() {
        KPABERW13SecretKeySerParameter oriSecretKeyParameter = (KPABERW13SecretKeySerParameter) super.generateKey();
        return new KPABEHW14SecretKeySerParameter(
                oriSecretKeyParameter.getParameters(),
                oriSecretKeyParameter.getAccessControlParameter(),
                oriSecretKeyParameter.getK0s(),
                oriSecretKeyParameter.getK1s(),
                oriSecretKeyParameter.getK2s()
        );
    }
}

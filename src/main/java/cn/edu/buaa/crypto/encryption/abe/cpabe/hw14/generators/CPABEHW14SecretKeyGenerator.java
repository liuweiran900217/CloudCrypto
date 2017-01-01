package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13SecretKeySerParameter;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE secret key generator.
 */
public class CPABEHW14SecretKeyGenerator extends CPABERW13SecretKeyGenerator {
    public PairingKeySerParameter generateKey() {
        CPABERW13SecretKeySerParameter oriSecretKeyParameter = (CPABERW13SecretKeySerParameter) super.generateKey();
        return new CPABEHW14SecretKeySerParameter(
                oriSecretKeyParameter.getParameters(),
                oriSecretKeyParameter.getK0(),
                oriSecretKeyParameter.getK1(),
                oriSecretKeyParameter.getK2s(),
                oriSecretKeyParameter.getK3s()
        );
    }
}

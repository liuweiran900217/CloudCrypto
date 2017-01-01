package cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.KPABELLW14MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.KPABELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13PublicKeySerParameter;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Liu-Liu-Wu-14 CCA2-secure KP-ABE public key / master secret key generator.
 */
public class KPABELLW14KeyPairGenerator extends KPABERW13KeyPairGenerator {
    public PairingKeySerPair generateKeyPair() {
        PairingKeySerPair pairingKeySerPair = super.generateKeyPair();
        KPABERW13PublicKeySerParameter publicKeyRW13Parameter = (KPABERW13PublicKeySerParameter) pairingKeySerPair.getPublic();
        KPABERW13MasterSecretKeySerParameter masterKeyRW13Parameter = (KPABERW13MasterSecretKeySerParameter) pairingKeySerPair.getPrivate();
        AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator = this.parameters.getChameleonHashKeyPairGenerator();
        KeyGenerationParameters chameleonHashKeyGenerationParameter = this.parameters.getChameleonHashKeyGenerationParameter();
        chameleonHashKeyPairGenerator.init(chameleonHashKeyGenerationParameter);
        AsymmetricKeySerPair keyPair = chameleonHashKeyPairGenerator.generateKeyPair();
        AsymmetricKeySerParameter chameleonHashPublicKey = keyPair.getPublic();

        KPABELLW14PublicKeySerParameter publicKeyParameter = new KPABELLW14PublicKeySerParameter(
                publicKeyRW13Parameter.getParameters(),
                chameleonHashPublicKey,
                publicKeyRW13Parameter.getG(),
                publicKeyRW13Parameter.getU(),
                publicKeyRW13Parameter.getH(),
                publicKeyRW13Parameter.getW(),
                publicKeyRW13Parameter.getEggAlpha()
        );
        KPABELLW14MasterSecretKeySerParameter masterKeyParameter = new KPABELLW14MasterSecretKeySerParameter(
                masterKeyRW13Parameter.getParameters(),
                masterKeyRW13Parameter.getAlpha()
        );
        return new PairingKeySerPair(publicKeyParameter, masterKeyParameter);
    }
}

package cn.edu.buaa.crypto.encryption.re.lsw10a;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.REEngine;
import cn.edu.buaa.crypto.encryption.re.genparams.REDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.genparams.REEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.genparams.REKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.genparams.RESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.generators.RELSW10aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters Revocation Encryption engine.
 */
public class RELSW10aEngine extends REEngine {
    private static final String SCHEME_NAME = "Lewko-Waters-08a Revocation Encryption";

    private static RELSW10aEngine engine;

    public static RELSW10aEngine getInstance() {
        if (engine == null) {
            engine = new RELSW10aEngine();
        }
        return engine;
    }

    private RELSW10aEngine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters) {
        RELSW10aKeyPairGenerator keyPairGenerator = new RELSW10aKeyPairGenerator();
        keyPairGenerator.init(new REKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {
        if (!(publicKey instanceof RELSW10aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELSW10aPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof RELSW10aMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, RELSW10aMasterSecretKeySerParameter.class.getName());
        }
        RELSW10aSecretKeyGenerator secretKeyGenerator = new RELSW10aSecretKeyGenerator();
        secretKeyGenerator.init(new RESecretKeyGenerationParameter(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof RELSW10aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELSW10aPublicKeySerParameter.class.getName());
        }
        RELSW10aEncryptionGenerator encryptionGenerator = new RELSW10aEncryptionGenerator();
        encryptionGenerator.init(new REEncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
        if (!(publicKey instanceof RELSW10aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELSW10aPublicKeySerParameter.class.getName());
        }
        RELSW10aEncryptionGenerator encryptionGenerator = new RELSW10aEncryptionGenerator();
        encryptionGenerator.init(new REEncryptionGenerationParameter(publicKey, ids, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof RELSW10aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELSW10aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RELSW10aSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RELSW10aSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof RELSW10aCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, RELSW10aCiphertextSerParameter.class.getName());
        }
        RELSW10aDecryptionGenerator decryptionGenerator = new RELSW10aDecryptionGenerator();
        decryptionGenerator.init(new REDecryptionGenerationParameter(
                publicKey, secretKey, ids, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String[] ids, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof RELSW10aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELSW10aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RELSW10aSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RELSW10aSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof RELSW10aHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, RELSW10aHeaderSerParameter.class.getName());
        }
        RELSW10aDecryptionGenerator decryptionGenerator = new RELSW10aDecryptionGenerator();
        decryptionGenerator.init(new REDecryptionGenerationParameter(
                publicKey, secretKey, ids, header));
        return decryptionGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

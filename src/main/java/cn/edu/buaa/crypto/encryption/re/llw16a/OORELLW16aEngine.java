package cn.edu.buaa.crypto.encryption.re.llw16a;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.re.OOREEngine;
import cn.edu.buaa.crypto.encryption.re.genparams.*;
import cn.edu.buaa.crypto.encryption.re.llw16a.generators.*;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CPA-secure RE engine.
 */
public class OORELLW16aEngine extends OOREEngine {
    private static final String SCHEME_NAME = "Liu-Liu-Wu-16 CPA-secure Revocation Encryption";

    private static OORELLW16aEngine engine;

    public static OORELLW16aEngine getInstance() {
        if (engine == null) {
            engine = new OORELLW16aEngine();
        }
        return engine;
    }

    private OORELLW16aEngine() {
        super(SCHEME_NAME, ProveSecModel.Standard, PayloadSecLevel.CPA, PredicateSecLevel.NON_ANON);
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters) {
        RELLW16aKeyPairGenerator keyPairGenerator = new RELLW16aKeyPairGenerator();
        keyPairGenerator.init(new REKeyPairGenerationParameter(pairingParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {
        if (!(publicKey instanceof RELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof RELLW16aMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, RELLW16aMasterSecretKeySerParameter.class.getName());
        }
        RELLW16aSecretKeyGenerator secretKeyGenerator = new RELLW16aSecretKeyGenerator();
        secretKeyGenerator.init(new RESecretKeyGenerationParameter(
                publicKey, masterKey, id));
        return secretKeyGenerator.generateKey();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String[] ids, Element message){
        if (!(publicKey instanceof RELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16aPublicKeySerParameter.class.getName());
        }
        RELLW16aEncryptionGenerator encryptionGenerator = new RELLW16aEncryptionGenerator();
        encryptionGenerator.init(new REEncryptionGenerationParameter(publicKey, ids, message));

        return encryptionGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids) {
        if (!(publicKey instanceof RELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16aPublicKeySerParameter.class.getName());
        }
        RELLW16aEncryptionGenerator encryptionGenerator = new RELLW16aEncryptionGenerator();
        encryptionGenerator.init(new REEncryptionGenerationParameter(publicKey, ids, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String[] ids, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof RELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RELLW16aSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RELLW16aSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof RELLW16aCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, RELLW16aCiphertextSerParameter.class.getName());
        }
        RELLW16aDecryptionGenerator decryptionGenerator = new RELLW16aDecryptionGenerator();
        decryptionGenerator.init(new REDecryptionGenerationParameter(
                publicKey, secretKey, ids, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String[] ids, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof RELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof RELLW16aSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, RELLW16aSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof RELLW16aHeaderSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, RELLW16aHeaderSerParameter.class.getName());
        }
        RELLW16aDecryptionGenerator decryptionGenerator = new RELLW16aDecryptionGenerator();
        decryptionGenerator.init(new REDecryptionGenerationParameter(
                publicKey, secretKey, ids, header));
        return decryptionGenerator.recoverKey();
    }

    public PairingCipherSerParameter offlineEncryption(PairingKeySerParameter publicKey, int n) {
        if (!(publicKey instanceof RELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16aPublicKeySerParameter.class.getName());
        }
        RELLW16aIntermediateGenerator intermediateGenerator = new RELLW16aIntermediateGenerator();
        intermediateGenerator.init(new REIntermediateGenerationParameter(publicKey, n));
        return intermediateGenerator.generateCiphertext();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] ids) {
        if (!(publicKey instanceof RELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof RELLW16aIntermediateSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, RELLW16aIntermediateSerParameter.class.getName());
        }
        RELLW16aEncryptionGenerator encryptionGenerator = new RELLW16aEncryptionGenerator();
        REEncryptionGenerationParameter encryptionGenerationParameter
                = new REEncryptionGenerationParameter(publicKey, ids, null);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateEncryptionPair();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, PairingCipherSerParameter intermediate, String[] ids, Element message) {
        if (!(publicKey instanceof RELLW16aPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, RELLW16aPublicKeySerParameter.class.getName());
        }
        if (!(intermediate instanceof RELLW16aIntermediateSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, intermediate, RELLW16aIntermediateSerParameter.class.getName());
        }
        RELLW16aEncryptionGenerator encryptionGenerator = new RELLW16aEncryptionGenerator();
        REEncryptionGenerationParameter encryptionGenerationParameter
                = new REEncryptionGenerationParameter(publicKey, ids, message);
        encryptionGenerationParameter.setIntermediate(intermediate);
        encryptionGenerator.init(encryptionGenerationParameter);
        return encryptionGenerator.generateCiphertext();
    }
}

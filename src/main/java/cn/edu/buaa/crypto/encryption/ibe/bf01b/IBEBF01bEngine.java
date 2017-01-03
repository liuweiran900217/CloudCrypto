package cn.edu.buaa.crypto.encryption.ibe.bf01b;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.generators.IBEBF01bDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.generators.IBEBF01bEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.generators.IBEBF01bKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.generators.IBEBF01bSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEKeyPairGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBESecretKeyGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE engine.
 */
public class IBEBF01bEngine extends IBEEngine {
    //Scheme name, used for exceptions
    private static final String SCHEME_NAME = "Boneh-Franklin CPA-secure IBE";

    private static IBEBF01bEngine engine;

    public static IBEBF01bEngine getInstance() {
        if (engine == null) {
            engine = new IBEBF01bEngine();
        }
        return engine;
    }

    private IBEBF01bEngine() {
        super(SCHEME_NAME, ProveSecModel.RandomOracle, PayloadSecLevel.CCA2, PredicateSecLevel.ANON);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters) {
        IBEBF01bKeyPairGenerator keyPairGenerator = new IBEBF01bKeyPairGenerator();
        keyPairGenerator.init(new IBEKeyPairGenerationParameter(pairingParameters));

        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {
        if (!(publicKey instanceof IBEBF01bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEBF01bPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof IBEBF01bMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, masterKey, IBEBF01bMasterSecretKeySerParameter.class.getName());
        }
        IBEBF01bSecretKeyGenerator secretKeyGenerator = new IBEBF01bSecretKeyGenerator();
        secretKeyGenerator.init(new IBESecretKeyGenerationParameter(
                publicKey, masterKey, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String id){
        if (!(publicKey instanceof IBEBF01bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEBF01bPublicKeySerParameter.class.getName());
        }
        IBEBF01bEncryptionGenerator encryptionGenerator = new IBEBF01bEncryptionGenerator();
        encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, null));

        return encryptionGenerator.generateEncryptionPair();
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String id, Element message){
        if (!(publicKey instanceof IBEBF01bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEBF01bPublicKeySerParameter.class.getName());
        }
        IBEBF01bEncryptionGenerator encryptionGenerator = new IBEBF01bEncryptionGenerator();
        encryptionGenerator.init(new IBEEncryptionGenerationParameter(publicKey, id, message));

        return encryptionGenerator.generateCiphertext();
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              String id, PairingCipherSerParameter ciphertext) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBEBF01bPublicKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEBF01bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof IBEBF01bSecretKeySerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, IBEBF01bSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof IBEBF01bCiphertextSerParameter)){
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, ciphertext, IBEBF01bCiphertextSerParameter.class.getName());
        }
        IBEBF01bDecryptionGenerator decryptionGenerator = new IBEBF01bDecryptionGenerator();
        decryptionGenerator.init(new IBEDecryptionGenerationParameter(
                publicKey, secretKey, id, ciphertext));
        return decryptionGenerator.recoverMessage();
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String id, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(publicKey instanceof IBEBF01bPublicKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, publicKey, IBEBF01bPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof IBEBF01bSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, secretKey, IBEBF01bSecretKeySerParameter.class.getName());
        }
        if (!(header instanceof IBEBF01aHeaderSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(SCHEME_NAME, header, IBEBF01aHeaderSerParameter.class.getName());
        }
        IBEBF01bDecryptionGenerator decryptionGenerator = new IBEBF01bDecryptionGenerator();
        decryptionGenerator.init(new IBEDecryptionGenerationParameter(
                publicKey, secretKey, id, header));
        return decryptionGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}
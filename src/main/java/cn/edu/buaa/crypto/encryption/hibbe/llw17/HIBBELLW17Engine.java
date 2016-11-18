package cn.edu.buaa.crypto.encryption.hibbe.llw17;

import cn.edu.buaa.crypto.algebra.genparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.HIBBEEngine;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.generators.HIBBELLW17DecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.generators.HIBBELLW17EncapsulationPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.generators.HIBBELLW17KeyPairGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.generators.HIBBELLW17SecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams.*;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17CipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17MasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE engine.
 */
public class HIBBELLW17Engine implements HIBBEEngine {
    public static final String SCHEME_NAME = "Liu-Liu-Wu-17 CCA2-secure composite-order HIBBE";
    private static HIBBELLW17Engine engine;

    private Digest digest = new SHA256Digest();

    public void setDigest(Digest digest) {
        this.digest = digest;
    }

    public static HIBBELLW17Engine getInstance() {
        if (engine == null) {
            engine = new HIBBELLW17Engine();
        }
        return engine;
    }



    private HIBBELLW17Engine() {

    }

    public AsymmetricKeySerPair setup(PairingParameters pairingParameters, int maxUser) {
        HIBBELLW17KeyPairGenerator keyPairGenerator = new HIBBELLW17KeyPairGenerator();
        keyPairGenerator.init(new HIBBELLW17KeyPairGenerationParameter(pairingParameters, maxUser));

        return keyPairGenerator.generateKeyPair();
    }

    public AsymmetricKeySerParameter keyGen(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter masterKey, String[] ids) {
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW17PublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof HIBBELLW17MasterSecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + masterKey.getClass().getName() + ", require"
                            + HIBBELLW17MasterSecretKeySerParameter.class.getName());
        }
        HIBBELLW17SecretKeyGenerator secretKeyGenerator = new HIBBELLW17SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW17SecretKeyGenerationParameter(
                publicKey, masterKey, ids));

        return secretKeyGenerator.generateKey();
    }

    public AsymmetricKeySerParameter delegate(AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, int index, String id) {
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW17PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW17SecretKeySerParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require"
                            + HIBBELLW17SecretKeySerParameter.class.getName());
        }
        HIBBELLW17SecretKeyGenerator secretKeyGenerator = new HIBBELLW17SecretKeyGenerator();
        secretKeyGenerator.init(new HIBBELLW17DelegateGenerationParameter(
                publicKey, secretKey, index, id));

        return secretKeyGenerator.generateKey();
    }

    public PairingKeyEncapsulationSerPair encapsulation(AsymmetricKeySerParameter publicKey, String... ids){
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW17PublicKeySerParameter.class.getName());
        }
        HIBBELLW17EncapsulationPairGenerator keyEncapsulationPairGenerator = new HIBBELLW17EncapsulationPairGenerator();
        keyEncapsulationPairGenerator.init(new HIBBELLW17CiphertextGenerationParameter(
                digest, publicKey, ids));

        return keyEncapsulationPairGenerator.generateEncryptionPair();
    }

    public byte[] decapsulation (AsymmetricKeySerParameter publicKey, AsymmetricKeySerParameter secretKey, String[] ids, PairingCipherSerParameter ciphertext)
            throws InvalidCipherTextException {
        if (!(publicKey instanceof HIBBELLW17PublicKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + HIBBELLW17PublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof HIBBELLW17SecretKeySerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + secretKey.getClass().getName() + ", require "
                            + HIBBELLW17SecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof HIBBELLW17CipherSerParameter)){
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + SCHEME_NAME  + ", find "
                            + ciphertext.getClass().getName() + ", require "
                            + HIBBELLW17CipherSerParameter.class.getName());
        }
        HIBBELLW17DecapsulationGenerator keyDecapsulationGenerator = new HIBBELLW17DecapsulationGenerator();
        keyDecapsulationGenerator.init(new HIBBELLW17DecapsulationParameter(
                digest, publicKey, secretKey, ids, ciphertext));
        return keyDecapsulationGenerator.recoverKey();
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }
}

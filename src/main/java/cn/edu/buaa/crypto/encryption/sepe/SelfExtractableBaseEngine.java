package cn.edu.buaa.crypto.encryption.sepe;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.sepe.serparams.SEPEHeaderParameter;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2016/12/4.
 *
 * Generic self-extractable engine.
 */
public class SelfExtractableBaseEngine extends Engine {
    private static final int default_iteration_time = 4096;

    private final String engine_name;
    private final BlockCipher blockCipher;
    private final PBEParametersGenerator pbeParametersGenerator;
    private final Digest digest;
    private final SecureRandom secureRandom;

    public SelfExtractableBaseEngine(Engine engine, PBEParametersGenerator pbeParametersGenerator, BlockCipher blockCipher, Digest digest) {
        super(engine.getEngineName(), engine.getProveSecModel(), engine.getPayloadSecLevel(), engine.getPredicateSecLevel());
        if (!engine.getPayloadSecLevel().equals(Engine.PayloadSecLevel.CPA)
                || digest.getDigestSize() < blockCipher.getBlockSize()) {
            throw new IllegalArgumentException("Self-extractable encapsulation requires CPA-secure engine");
        }
        this.pbeParametersGenerator = pbeParametersGenerator;
        this.blockCipher = blockCipher;
        this.digest = digest;
        this.secureRandom = new SecureRandom();
        this.engine_name = "Self-Extractable " + engine.getEngineName()
                + ", with BlockCipher " + this.blockCipher.getAlgorithmName()
                + ", with Digest " + this.digest.getAlgorithmName();
    }

    public String getEngineName() {
        return this.engine_name;
    }

    public byte[] selfKeyGen() {
        byte[] ek = new byte[blockCipher.getBlockSize()];
        secureRandom.nextBytes(ek);
        return ek;
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeyEncapsulationSerPair encapsulationPair, byte[] ek) {
        PairingCipherSerParameter ciphertext = encapsulationPair.getHeader();
        try {
            //get the session key
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(ciphertext);
            byte[] byteArrayCiphertext = byteArrayOutputStream.toByteArray();
            objectOutputStream.close();
            byteArrayOutputStream.close();
            this.pbeParametersGenerator.init(ek, byteArrayCiphertext, default_iteration_time);
            KeyParameter sessionKeyParameter = (KeyParameter) this.pbeParametersGenerator.generateDerivedParameters(this.blockCipher.getBlockSize() * 8);
            byte[] sessionKey = sessionKeyParameter.getKey();

            //encrypt sessionKey under k_prime
            byte[] k_prime_temp = encapsulationPair.getSessionKey();
            byte[] k_prime_long = new byte[digest.getDigestSize()];
            digest.reset();
            digest.update(k_prime_temp, 0, k_prime_temp.length);
            digest.doFinal(k_prime_long, 0);
            byte[] k_prime = new byte[blockCipher.getBlockSize()];
            System.arraycopy(k_prime_long, 0, k_prime, 0, k_prime.length);
            KeyParameter blockCipherKeyParameter = new KeyParameter(k_prime);
            blockCipher.init(true, blockCipherKeyParameter);
            byte[] ct_k = new byte[blockCipher.getBlockSize()];
            blockCipher.processBlock(sessionKey, 0, ct_k, 0);
            //return the result
            return new PairingKeyEncapsulationSerPair(
                    sessionKey,
                    new SEPEHeaderParameter(ciphertext, ct_k)
            );
        } catch (IOException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("cannot serialize IBE ciphertext");
        }
    }

    public byte[] decapsulation(byte[] k_prime_temp, byte[] ct_k) {
        byte[] k_prime_long = new byte[digest.getDigestSize()];
        digest.reset();
        digest.update(k_prime_temp, 0, k_prime_temp.length);
        digest.doFinal(k_prime_long, 0);
        byte[] k_prime = new byte[blockCipher.getBlockSize()];
        System.arraycopy(k_prime_long, 0, k_prime, 0, k_prime.length);
        KeyParameter blockCipherKeyParameter = new KeyParameter(k_prime);
        blockCipher.init(false, blockCipherKeyParameter);
        byte[] sessionKey = new byte[blockCipher.getBlockSize()];
        blockCipher.processBlock(ct_k, 0, sessionKey, 0);
        return sessionKey;
    }

    public byte[] selfDecapsulation(byte[] ek, PairingCipherSerParameter header) {
        if (!(header instanceof SEPEHeaderParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + this.engine_name  + ", find "
                            + header.getClass().getName() + ", require "
                            + SEPEHeaderParameter.class.getName());
        }
        SEPEHeaderParameter seHeaderParameter = (SEPEHeaderParameter)header;
        PairingCipherSerParameter ct_y = seHeaderParameter.getCtY();

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(ct_y);
            byte[] byteArrayCiphertext = byteArrayOutputStream.toByteArray();
            objectOutputStream.close();
            byteArrayOutputStream.close();
            this.pbeParametersGenerator.init(ek, byteArrayCiphertext, default_iteration_time);
            KeyParameter sessionKeyParameter = (KeyParameter) this.pbeParametersGenerator.generateDerivedParameters(this.blockCipher.getBlockSize() * 8);
            return sessionKeyParameter.getKey();
        } catch (IOException e) {
            e.printStackTrace();
            throw new IllegalArgumentException("cannot de-serialize ciphertext");
        }
    }
}

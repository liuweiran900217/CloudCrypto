package cn.edu.buaa.crypto.encryption.sepe;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.IBEEngine;
import cn.edu.buaa.crypto.encryption.sepe.serparams.SEPEHeaderParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;

/**
 * Created by Weiran Liu on 2016/12/4.
 *
 * Self-extractable IBE engine.
 */
public class SelfExtractableIBEEngine extends Engine {
    private final IBEEngine engine;
    private final SelfExtractableBaseEngine selfExtractableBaseEngine;

    public SelfExtractableIBEEngine(IBEEngine engine, PBEParametersGenerator pbeParametersGenerator, BlockCipher blockCipher, Digest digest) {
        super(engine.getEngineName(), engine.getProveSecModel(), engine.getPayloadSecLevel(), engine.getPredicateSecLevel());

        this.engine = engine;
        this.selfExtractableBaseEngine = new SelfExtractableBaseEngine(engine, pbeParametersGenerator, blockCipher, digest);
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters) {
        return engine.setup(pairingParameters);
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id) {
        return engine.keyGen(publicKey, masterKey, id);
    }

    public byte[] selfKeyGen() {
        return this.selfExtractableBaseEngine.selfKeyGen();
    }

    public PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String id, byte[] ek){
        PairingKeyEncapsulationSerPair encapsulationPair = this.engine.encapsulation(publicKey, id);
        return this.selfExtractableBaseEngine.encapsulation(encapsulationPair, ek);
    }

    public byte[] decapsulation(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                                String id, PairingCipherSerParameter header) throws InvalidCipherTextException {
        if (!(header instanceof SEPEHeaderParameter)) {
            throw new IllegalArgumentException
                    ("Invalid CipherParameter Instance of " + this.selfExtractableBaseEngine.getEngineName()  + ", find "
                            + header.getClass().getName() + ", require "
                            + SEPEHeaderParameter.class.getName());
        }
        SEPEHeaderParameter seHeaderParameter = (SEPEHeaderParameter)header;
        PairingCipherSerParameter headerParameter = seHeaderParameter.getCtY();
        byte[] ct_k = seHeaderParameter.getCtK();
        byte[] k_prime_temp = this.engine.decapsulation(publicKey, secretKey, id, headerParameter);
        return this.selfExtractableBaseEngine.decapsulation(k_prime_temp, ct_k);
    }

    public byte[] selfDecapsulation(byte[] ek, PairingCipherSerParameter header) throws InvalidCipherTextException {
        return this.selfExtractableBaseEngine.selfDecapsulation(ek, header);
    }

    public String getEngineName() {
        return this.selfExtractableBaseEngine.getEngineName();
    }
}

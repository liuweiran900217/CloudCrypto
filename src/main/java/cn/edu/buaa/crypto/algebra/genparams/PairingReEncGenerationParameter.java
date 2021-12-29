package cn.edu.buaa.crypto.algebra.genparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;


public abstract class PairingReEncGenerationParameter implements CipherParameters {

    private PairingKeySerParameter publicKeyParameter;
    private PairingKeySerParameter reKeyParameter;
    private PairingCipherSerParameter cipherParameter;

    public PairingReEncGenerationParameter(PairingKeySerParameter publicKeyParameter,
                                           PairingKeySerParameter reKeyParameter,
                                           PairingCipherSerParameter cipherParameter) {
        this.publicKeyParameter = publicKeyParameter;
        this.reKeyParameter = reKeyParameter;
        this.cipherParameter = cipherParameter;
    }

    public PairingKeySerParameter getPublicKeyParameter() {
        return this.publicKeyParameter;
    }

    public PairingKeySerParameter getReKeyParameter() {
        return this.reKeyParameter;
    }

    public PairingCipherSerParameter getCipherParameter() {
        return this.cipherParameter;
    }
}
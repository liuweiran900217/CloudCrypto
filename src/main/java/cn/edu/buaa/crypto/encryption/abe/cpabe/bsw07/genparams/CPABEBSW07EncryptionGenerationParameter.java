package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.genparams;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.algebra.genparams.PairingEncryptionGenerationParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams.CPABEBSW07PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/19.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE ciphertext generation parameter.
 */
public class CPABEBSW07EncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private CPABEBSW07PublicKeySerParameter publicKeyParameters;
    private AccessControlEngine accessControlEngine;
    private int[][] accessPolicy;
    private String[] rhos;

    public CPABEBSW07EncryptionGenerationParameter(
            AccessControlEngine accessControlEngine, PairingKeySerParameter publicKeyParameter,
            int[][] accessPolicy, String[] rhos, Element message) {
        super(publicKeyParameter, message);
        this.accessControlEngine = accessControlEngine;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }

    public AccessControlEngine getAccessControlEngine() {
        return this.accessControlEngine;
    }

    public int[][] getAccessPolicy() { return this.accessPolicy; }

    public String[] getRhos() { return this.rhos; }
}

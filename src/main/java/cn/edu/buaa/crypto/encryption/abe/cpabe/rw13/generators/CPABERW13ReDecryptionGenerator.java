package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingReDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEReDecGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.*;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import static cn.edu.buaa.crypto.utils.PairingUtils.PairingGroupType.G1;
import static cn.edu.buaa.crypto.utils.PairingUtils.PairingGroupType.GT;


public class CPABERW13ReDecryptionGenerator implements PairingReDecryptionGenerator {
    protected CPABEReDecGenerationParameter parameter;
    protected Element sessionKey;
    protected Element decMessage;

    public void init(CipherParameters params) {
        this.parameter = (CPABEReDecGenerationParameter) params;
    }

    protected void computeDecapsulation() throws InvalidCipherTextException {
        CPABERW13PublicKeySerParameter publicKeyParameter =
                (CPABERW13PublicKeySerParameter) this.parameter.getPublicKeyParameter();
        CPABERW13IDSecretKeySerParameter IDSecretKeyParameter =
                (CPABERW13IDSecretKeySerParameter) this.parameter.getSecretKeyParameter();
        CPABERW13ReEncCiphertextSerParameter reEncCiphertextParameter =
                (CPABERW13ReEncCiphertextSerParameter) this.parameter.getCiphertextParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        this.sessionKey = pairing.pairing(IDSecretKeyParameter.getK0(), reEncCiphertextParameter.getC2_());
        Element A = pairing.pairing(IDSecretKeyParameter.getK1(), reEncCiphertextParameter.getC1_());
        sessionKey = sessionKey.div(A).getImmutable();
        Element g_t_ = reEncCiphertextParameter.getC0_()
                .div(PairingUtils.MapByteArrayToGroup(pairing, this.sessionKey.toBytes(), G1)).getImmutable();
        sessionKey = pairing.pairing(g_t_, reEncCiphertextParameter.getC3_());

        this.decMessage = PairingUtils.MapByteArrayToGroup(pairing,
                reEncCiphertextParameter.getC_().toBytes(), GT).mul(sessionKey).getImmutable();
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        CPABERW13ReEncCiphertextSerParameter ciphertextParameter =
                (CPABERW13ReEncCiphertextSerParameter) this.parameter.getCiphertextParameter();
        return ciphertextParameter.getC_().mul(this.sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}

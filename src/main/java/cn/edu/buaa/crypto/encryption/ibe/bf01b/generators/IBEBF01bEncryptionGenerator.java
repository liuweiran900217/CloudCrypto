package cn.edu.buaa.crypto.encryption.ibe.bf01b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE encryption generator.
 */
public class IBEBF01bEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {

    private IBEEncryptionGenerationParameter params;
    private IBEBF01bPublicKeySerParameter publicKeyParameter;

    public void init(CipherParameters params) {
        this.params = (IBEEncryptionGenerationParameter) params;
        this.publicKeyParameter = (IBEBF01bPublicKeySerParameter) this.params.getPublicKeyParameter();
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String id = this.params.getId();
        Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingUtils.PairingGroupType.G1).getImmutable();

        Element sigma = pairing.getGT().newRandomElement().getImmutable();
        byte[] byteArraySigma = sigma.toBytes();
        Element sessionKey = PairingUtils.MapByteArrayToGroup(pairing, byteArraySigma, PairingUtils.PairingGroupType.GT);
        Element r = PairingUtils.MapByteArrayToGroup(pairing, byteArraySigma, PairingUtils.PairingGroupType.Zr);
        Element U = publicKeyParameter.getG().powZn(r).getImmutable();
        Element V = sigma.mul(PairingUtils.MapByteArrayToGroup(
                pairing,
                pairing.pairing(elementId, publicKeyParameter.getGs()).powZn(r).toBytes(),
                PairingUtils.PairingGroupType.GT
        )).getImmutable();

        return new PairingKeyEncapsulationSerPair(sessionKey.toBytes(),
                new IBEBF01bHeaderSerParameter(publicKeyParameter.getParameters(), U, V));
    }

    public PairingCipherSerParameter generateCiphertext() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String id = this.params.getId();
        Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingUtils.PairingGroupType.G1).getImmutable();

        Element sigma = pairing.getGT().newRandomElement().getImmutable();
        Element message = this.params.getMessage().getImmutable();
        byte[] byteArraySigma = sigma.toBytes();
        byte[] byteArrayMessage = message.toBytes();
        byte[] byteArrayH3 = new byte[byteArraySigma.length + byteArrayMessage.length];
        System.arraycopy(byteArraySigma, 0, byteArrayH3, 0, byteArraySigma.length);
        System.arraycopy(byteArrayMessage, 0, byteArrayH3, byteArraySigma.length, byteArrayMessage.length);
        Element sessionKey = PairingUtils.MapByteArrayToGroup(pairing, byteArraySigma, PairingUtils.PairingGroupType.GT);
        Element r = PairingUtils.MapByteArrayToGroup(pairing, byteArrayH3, PairingUtils.PairingGroupType.Zr);
        Element U = publicKeyParameter.getG().powZn(r).getImmutable();
        Element V = sigma.mul(PairingUtils.MapByteArrayToGroup(
                pairing,
                pairing.pairing(elementId, publicKeyParameter.getGs()).powZn(r).toBytes(),
                PairingUtils.PairingGroupType.GT
        )).getImmutable();

        Element W = sessionKey.mul(this.params.getMessage()).getImmutable();
        return new IBEBF01bCiphertextSerParameter(publicKeyParameter.getParameters(), U, V, W);
    }
}
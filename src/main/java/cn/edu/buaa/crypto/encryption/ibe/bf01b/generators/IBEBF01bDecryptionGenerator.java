package cn.edu.buaa.crypto.encryption.ibe.bf01b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE decryption generator.
 */
public class IBEBF01bDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private IBEDecryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (IBEDecryptionGenerationParameter)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        IBEBF01bPublicKeySerParameter publicKeyParameter = (IBEBF01bPublicKeySerParameter)this.params.getPublicKeyParameter();
        IBEBF01bSecretKeySerParameter secretKeyParameter = (IBEBF01bSecretKeySerParameter)this.params.getSecretKeyParameter();
        IBEBF01bHeaderSerParameter ciphertextParameter = (IBEBF01bHeaderSerParameter) this.params.getCiphertextParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element elementIdCT = PairingUtils.MapStringToGroup(pairing, this.params.getId(), PairingUtils.PairingGroupType.G1);

        if (!secretKeyParameter.getElementId().equals(elementIdCT)){
            throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector");
        }

        Element sigma = ciphertextParameter.getV().div(PairingUtils.MapByteArrayToGroup(
                pairing,
                pairing.pairing(secretKeyParameter.getD(), ciphertextParameter.getU()).toBytes(),
                PairingUtils.PairingGroupType.GT
        )).getImmutable();
        byte[] byteArraySigma = sigma.toBytes();
        Element sessionKey = PairingUtils.MapByteArrayToGroup(pairing, byteArraySigma, PairingUtils.PairingGroupType.GT).getImmutable();
        Element r = PairingUtils.MapByteArrayToGroup(pairing, byteArraySigma, PairingUtils.PairingGroupType.Zr);
        if (!publicKeyParameter.getG().powZn(r).equals(ciphertextParameter.getU())) {
            throw new InvalidCipherTextException("Invalid ciphertext");
        }
        return sessionKey.toBytes();
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        IBEBF01bPublicKeySerParameter publicKeyParameter = (IBEBF01bPublicKeySerParameter)this.params.getPublicKeyParameter();
        IBEBF01bSecretKeySerParameter secretKeyParameter = (IBEBF01bSecretKeySerParameter)this.params.getSecretKeyParameter();
        IBEBF01bCiphertextSerParameter ciphertextParameter = (IBEBF01bCiphertextSerParameter) this.params.getCiphertextParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element elementIdCT = PairingUtils.MapStringToGroup(pairing, this.params.getId(), PairingUtils.PairingGroupType.G1);

        if (!secretKeyParameter.getElementId().equals(elementIdCT)){
            throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector");
        }

        Element sigma = ciphertextParameter.getV().div(PairingUtils.MapByteArrayToGroup(
                        pairing,
                        pairing.pairing(secretKeyParameter.getD(), ciphertextParameter.getU()).toBytes(),
                        PairingUtils.PairingGroupType.GT
                )).getImmutable();
        byte[] byteArraySigma = sigma.toBytes();
        Element message = ciphertextParameter.getW().div(PairingUtils.MapByteArrayToGroup(pairing, byteArraySigma, PairingUtils.PairingGroupType.GT)).getImmutable();
        byte[] byteArrayMessage = message.toBytes();
        byte[] byteArrayH3 = new byte[byteArraySigma.length + byteArrayMessage.length];
        System.arraycopy(byteArraySigma, 0, byteArrayH3, 0, byteArraySigma.length);
        System.arraycopy(byteArrayMessage, 0, byteArrayH3, byteArraySigma.length, byteArrayMessage.length);
        Element r = PairingUtils.MapByteArrayToGroup(pairing, byteArrayH3, PairingUtils.PairingGroupType.Zr);
        if (!publicKeyParameter.getG().powZn(r).equals(ciphertextParameter.getU())) {
            throw new InvalidCipherTextException("Invalid ciphertext");
        }
        return message;
    }
}

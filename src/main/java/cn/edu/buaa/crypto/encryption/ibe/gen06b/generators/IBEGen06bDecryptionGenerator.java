package cn.edu.buaa.crypto.encryption.ibe.gen06b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.IBEGen06bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.IBEGen06bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.IBEGen06bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.IBEGen06bSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Gentry CCA2-secure IBE decryption generator.
 */
public class IBEGen06bDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private IBEDecryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (IBEDecryptionGenerationParameter)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        IBEGen06bPublicKeySerParameter publicKeyParameter = (IBEGen06bPublicKeySerParameter)this.params.getPublicKeyParameter();
        IBEGen06bSecretKeySerParameter secretKeyParameter = (IBEGen06bSecretKeySerParameter)this.params.getSecretKeyParameter();
        IBEGen06bHeaderSerParameter ciphertextParameter = (IBEGen06bHeaderSerParameter) this.params.getCiphertextParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element elementIdCT = PairingUtils.MapStringToGroup(pairing, this.params.getId(), PairingUtils.PairingGroupType.Zr);

        if (!secretKeyParameter.getElementId().equals(elementIdCT)){
            throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector");
        }

        //verify ciphertext
        Element u = ciphertextParameter.getU().getImmutable();
        byte[] byteArrayU = u.toBytes();
        Element v = ciphertextParameter.getV().getImmutable();
        byte[] byteArrayV = v.toBytes();
        byte[] byteArrayH = new byte[byteArrayU.length + byteArrayV.length];
        System.arraycopy(byteArrayU, 0, byteArrayH, 0, byteArrayU.length);
        System.arraycopy(byteArrayV, 0, byteArrayH, byteArrayU.length, byteArrayV.length);
        Element beta = PairingUtils.MapByteArrayToGroup(pairing, byteArrayH, PairingUtils.PairingGroupType.Zr);
        if (!ciphertextParameter.getY().equals(
                pairing.pairing(u, secretKeyParameter.getHId2().mul(secretKeyParameter.getHId3().powZn(beta)))
                        .mul(v.powZn(secretKeyParameter.getRId2().add(secretKeyParameter.getRId3().mulZn(beta))))
        )) {
            throw new InvalidCipherTextException("Invalid ciphertext.");
        }
        return pairing.pairing(u, secretKeyParameter.getHId()).mul(v.powZn(secretKeyParameter.getRId())).toBytes();
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        IBEGen06bPublicKeySerParameter publicKeyParameter = (IBEGen06bPublicKeySerParameter)this.params.getPublicKeyParameter();
        IBEGen06bSecretKeySerParameter secretKeyParameter = (IBEGen06bSecretKeySerParameter)this.params.getSecretKeyParameter();
        IBEGen06bCiphertextSerParameter ciphertextParameter = (IBEGen06bCiphertextSerParameter) this.params.getCiphertextParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element elementIdCT = PairingUtils.MapStringToGroup(pairing, this.params.getId(), PairingUtils.PairingGroupType.Zr);

        if (!secretKeyParameter.getElementId().equals(elementIdCT)){
            throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector");
        }

        //verify ciphertext
        Element u = ciphertextParameter.getU().getImmutable();
        byte[] byteArrayU = u.toBytes();
        Element v = ciphertextParameter.getV().getImmutable();
        byte[] byteArrayV = v.toBytes();
        Element w = ciphertextParameter.getW().getImmutable();
        byte[] byteArrayW = w.toBytes();
        byte[] byteArrayH = new byte[byteArrayU.length + byteArrayV.length + byteArrayW.length];
        System.arraycopy(byteArrayU, 0, byteArrayH, 0, byteArrayU.length);
        System.arraycopy(byteArrayV, 0, byteArrayH, byteArrayU.length, byteArrayV.length);
        System.arraycopy(byteArrayW, 0, byteArrayH, byteArrayU.length + byteArrayV.length, byteArrayW.length);
        Element beta = PairingUtils.MapByteArrayToGroup(pairing, byteArrayH, PairingUtils.PairingGroupType.Zr);
        Element yPrime = pairing.pairing(u, secretKeyParameter.getHId2().mul(secretKeyParameter.getHId3().powZn(beta)))
                .mul(v.powZn(secretKeyParameter.getRId2().add(secretKeyParameter.getRId3().mulZn(beta))));
        if (!ciphertextParameter.getY().equals(yPrime)) {
            throw new InvalidCipherTextException("Invalid ciphertext.");
        }
        Element sessionKey = pairing.pairing(u, secretKeyParameter.getHId()).mul(v.powZn(secretKeyParameter.getRId())).getImmutable();
        return ciphertextParameter.getW().div(sessionKey).getImmutable();
    }
}
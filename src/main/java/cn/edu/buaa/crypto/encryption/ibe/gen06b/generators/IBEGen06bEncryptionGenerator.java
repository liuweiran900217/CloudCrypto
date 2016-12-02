package cn.edu.buaa.crypto.encryption.ibe.gen06b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.IBEGen06bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.IBEGen06bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams.IBEGen06bPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Gentry CCA2-secure IBE encryption generator.
 */
public class IBEGen06bEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {

    private IBEEncryptionGenerationParameter params;
    private IBEGen06bPublicKeySerParameter publicKeyParameter;

    public void init(CipherParameters params) {
        this.params = (IBEEncryptionGenerationParameter) params;
        this.publicKeyParameter = (IBEGen06bPublicKeySerParameter) this.params.getPublicKeyParameter();
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String id = this.params.getId();
        Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element u = publicKeyParameter.getG1().powZn(s).mul(publicKeyParameter.getG().powZn(elementId.mul(s).negate())).getImmutable();
        byte[] byteArrayU = u.toBytes();
        Element v = pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getG()).powZn(s).getImmutable();
        byte[] byteArrayV = v.toBytes();
        Element sessionKey = pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getH()).powZn(s).getImmutable();
        byte[] byteArrayH = new byte[byteArrayU.length + byteArrayV.length];
        System.arraycopy(byteArrayU, 0, byteArrayH, 0, byteArrayU.length);
        System.arraycopy(byteArrayV, 0, byteArrayH, byteArrayU.length, byteArrayV.length);
        Element beta = PairingUtils.MapByteArrayToGroup(pairing, byteArrayH, PairingUtils.PairingGroupType.Zr);
        Element y = pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getH2()).powZn(s)
                .mul(pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getH3()).powZn(s.mulZn(beta))).getImmutable();
        return new PairingKeyEncapsulationSerPair(sessionKey.toBytes(),
                new IBEGen06bHeaderSerParameter(publicKeyParameter.getParameters(), u, v, y));
    }

    public PairingCipherSerParameter generateCiphertext() {
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        String id = this.params.getId();
        Element elementId = PairingUtils.MapStringToGroup(pairing, id, PairingUtils.PairingGroupType.Zr).getImmutable();

        Element s = pairing.getZr().newRandomElement().getImmutable();
        Element u = publicKeyParameter.getG1().powZn(s).mul(publicKeyParameter.getG().powZn(elementId.mul(s).negate())).getImmutable();
        byte[] byteArrayU = u.toBytes();
        Element v = pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getG()).powZn(s).getImmutable();
        byte[] byteArrayV = v.toBytes();
        Element w = pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getH()).powZn(s).mul(params.getMessage()).getImmutable();
        byte[] byteArrayW = w.toBytes();
        byte[] byteArrayH = new byte[byteArrayU.length + byteArrayV.length + byteArrayW.length];
        System.arraycopy(byteArrayU, 0, byteArrayH, 0, byteArrayU.length);
        System.arraycopy(byteArrayV, 0, byteArrayH, byteArrayU.length, byteArrayV.length);
        System.arraycopy(byteArrayW, 0, byteArrayH, byteArrayU.length + byteArrayV.length, byteArrayW.length);
        Element beta = PairingUtils.MapByteArrayToGroup(pairing, byteArrayH, PairingUtils.PairingGroupType.Zr);
        Element y = pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getH2()).powZn(s)
                .mul(pairing.pairing(publicKeyParameter.getG(), publicKeyParameter.getH3()).powZn(s.mulZn(beta))).getImmutable();
        return new IBEGen06bCiphertextSerParameter(publicKeyParameter.getParameters(), u, v, w, y);
    }
}
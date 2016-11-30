package cn.edu.buaa.crypto.encryption.hibbe.llw16b.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingKeyPairGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw16b.serparams.HIBBELLW16bPublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Liu-Liu-Wu prime-order CCA2-secure HIBBE encryption generator.
 */
public class HIBBELLW16bEncryptionGenerator implements PairingEncryptionGenerator, PairingEncapsulationPairGenerator {
    private HIBBEEncryptionGenerationParameter params;
    private HIBBELLW16bPublicKeySerParameter publicKeyParameter;

    private PairingKeySerParameter signPublicKey;
    private PairingKeySerParameter signSecretKey;
    private Element sessionKey;
    private Element C0;
    private Element C1;

    public void init(CipherParameters params) {
        this.params = (HIBBEEncryptionGenerationParameter)params;
        this.publicKeyParameter = (HIBBELLW16bPublicKeySerParameter)this.params.getPublicKeyParameter();
    }

    private void computeEncapsulation() {
        //get sign key
        PairingKeyPairGenerator signKeyPairGenerator = params.getSignKeyPairGenerator();
        PairingKeySerPair signKeySerPair = signKeyPairGenerator.generateKeyPair();
        this.signPublicKey = signKeySerPair.getPublic();
        this.signSecretKey = signKeySerPair.getPrivate();

        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(signPublicKey);
            byte[] byteArraySignPublicKey = byteArrayOutputStream.toByteArray();
            objectOutputStream.close();
            byteArrayOutputStream.close();

            if (this.params.getIds().length != publicKeyParameter.getMaxUser()) {
                throw new IllegalArgumentException("Invalid identity vector set length");
            }
            Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
            String[] ids = this.params.getIds();
            Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);
            Element elementVk = PairingUtils.MapByteArrayToGroup(pairing, byteArraySignPublicKey, PairingUtils.PairingGroupType.Zr);
            Element beta = pairing.getZr().newRandomElement().getImmutable();

            this.sessionKey = pairing.pairing(publicKeyParameter.getG1(), publicKeyParameter.getG2()).powZn(beta).getImmutable();
            this.C0 = publicKeyParameter.getG().powZn(beta).getImmutable();
            this.C1 = publicKeyParameter.getG3().getImmutable();
            for (int i = 0; i < publicKeyParameter.getMaxUser(); i++) {
                if (ids[i] != null) {
                    C1 = C1.mul(publicKeyParameter.getUsAt(i).powZn(elementIds[i])).getImmutable();
                }
            }
            C1 = C1.mul(publicKeyParameter.getUv().powZn(elementVk)).getImmutable();
            C1 = C1.powZn(beta).getImmutable();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        try {
            Signer signer = this.params.getSigner();
            Element C2 = sessionKey.mul(this.params.getMessage()).getImmutable();
            byte[] byteArrayC0 = C0.toBytes();
            byte[] byteArrayC1 = C1.toBytes();
            byte[] byteArrayC2 = C2.toBytes();
            signer.init(true, signSecretKey);
            signer.update(byteArrayC0, 0, byteArrayC0.length);
            signer.update(byteArrayC1, 0, byteArrayC1.length);
            signer.update(byteArrayC2, 0, byteArrayC2.length);
            byte[] signature = signer.generateSignature();
            return new HIBBELLW16bCiphertextSerParameter(publicKeyParameter.getParameters(), signPublicKey, signature, C0, C1, C2);
        } catch (CryptoException e) {
            e.printStackTrace();
            return null;
        }
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        try {
            Signer signer = this.params.getSigner();
            byte[] byteArrayC0 = C0.toBytes();
            byte[] byteArrayC1 = C1.toBytes();
            signer.init(true, signSecretKey);
            signer.update(byteArrayC0, 0, byteArrayC0.length);
            signer.update(byteArrayC1, 0, byteArrayC1.length);
            byte[] signature = signer.generateSignature();
            return new PairingKeyEncapsulationSerPair(
                    this.sessionKey.toBytes(),
                    new HIBBELLW16bHeaderSerParameter(publicKeyParameter.getParameters(), signPublicKey, signature, C0, C1)
            );
        } catch (CryptoException e) {
            e.printStackTrace();
            return null;
        }
    }
}
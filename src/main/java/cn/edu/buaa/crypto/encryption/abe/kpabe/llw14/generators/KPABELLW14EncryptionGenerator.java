package cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.KPABELLW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.KPABELLW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams.KPABELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.generators.KPABERW13EncryptionGenerator;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Liu-Liu-Wu-14 CCA2-secure KP-ABE encryption generator.
 */
public class KPABELLW14EncryptionGenerator extends KPABERW13EncryptionGenerator {
    private ChameleonHasher chameleonHasher;
    private KPABELLW14PublicKeySerParameter publicKeyParameter;
    private Element C01;
    private Element C02;
    private byte[] chameleonHash;
    private byte[] r;

    public void init(CipherParameters parameter) {
        KPABEEncryptionGenerationParameter oriEncryptionParameter = (KPABEEncryptionGenerationParameter) parameter;
        this.chameleonHasher = oriEncryptionParameter.getChameleonHasher();
        this.publicKeyParameter = (KPABELLW14PublicKeySerParameter) oriEncryptionParameter.getPublicKeyParameter();

        Pairing pairing = PairingFactory.getPairing(oriEncryptionParameter.getPublicKeyParameter().getParameters());
        String[] attributes = oriEncryptionParameter.getAttributes();
        Element[] mappedElementAttributes = PairingUtils.MapStringArrayToFirstHalfZr(pairing, attributes);
        String[] mappedStringAttributes = PairingUtils.MapElementArrayToStringArray(mappedElementAttributes);
        KPABEEncryptionGenerationParameter resultEncryptionParameter = new KPABEEncryptionGenerationParameter(
                oriEncryptionParameter.getPublicKeyParameter(),
                mappedStringAttributes,
                oriEncryptionParameter.getMessage()
        );
        super.init(resultEncryptionParameter);
    }

    protected void computeEncapsulation() {
        super.computeEncapsulation();
        try {
            Pairing pairing = PairingFactory.getPairing(this.publicKeyParameter.getParameters());
            Element r0 = pairing.getZr().newRandomElement().getImmutable();
            this.C01 = publicKeyParameter.getG().powZn(r0).getImmutable();
            AsymmetricKeySerParameter chameleonHashPublicKey = publicKeyParameter.getChameleonHashPublicKey();
            chameleonHasher.init(false, chameleonHashPublicKey);
            byte[] byteArrayChPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
            chameleonHasher.update(byteArrayChPublicKey, 0, byteArrayChPublicKey.length);
            if (this.parameter.getMessage() != null) {
                Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
                byte[] byteArrayC = C.toBytes();
                chameleonHasher.update(byteArrayC, 0, byteArrayC.length);
            }
            byte[] byteArrayC0 = C0.toBytes();
            chameleonHasher.update(byteArrayC0, 0, byteArrayC0.length);
            byte[] byteArrayC01 = C01.toBytes();
            chameleonHasher.update(byteArrayC01, 0, byteArrayC01.length);
            String[] sortedAttributes = new String[this.parameter.getAttributes().length];
            System.arraycopy(this.parameter.getAttributes(), 0, sortedAttributes, 0, sortedAttributes.length);
            Arrays.sort(sortedAttributes);
            for (String attribute : sortedAttributes) {
                byte[] byteArrayAttribute = attribute.getBytes();
                chameleonHasher.update(byteArrayAttribute, 0, byteArrayAttribute.length);
                byte[] byteArrayC1i = C1s.get(attribute).toBytes();
                chameleonHasher.update(byteArrayC1i, 0, byteArrayC1i.length);
                byte[] byteArrayC2i = C2s.get(attribute).toBytes();
                chameleonHasher.update(byteArrayC2i, 0, byteArrayC2i.length);
            }
            byte[][] chResult = chameleonHasher.computeHash();
            this.chameleonHash = chResult[0];
            this.r = chResult[1];
            Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
            String mappedStringV = tempV.toString();
            Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
            this.C02 = publicKeyParameter.getU().powZn(V).mul(publicKeyParameter.getH()).powZn(r0)
                    .mul(publicKeyParameter.getW().powZn(s.negate())).getImmutable();
        } catch (IOException e) {
            throw new RuntimeException("Cannot serialize chk.");
        } catch (CryptoException e) {
            throw new RuntimeException("Cannot compute chameleon hash.");
        }
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        computeEncapsulation();
        return new PairingKeyEncapsulationSerPair(
                this.sessionKey.toBytes(),
                new KPABELLW14HeaderSerParameter(
                        publicKeyParameter.getParameters(), chameleonHash, r, C01, C02, C0, C1s, C2s));
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new KPABELLW14CiphertextSerParameter(
                publicKeyParameter.getParameters(), chameleonHash, r, C01, C02, C, C0, C1s, C2s);
    }
}
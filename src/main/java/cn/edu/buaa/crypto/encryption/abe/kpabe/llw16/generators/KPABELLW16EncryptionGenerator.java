package cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.kpabe.genparams.KPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.generators.KPABEHW14EncryptionGenerator;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.KPABELLW16CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.KPABELLW16HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.KPABELLW16IntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams.KPABELLW16PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.io.IOException;
import java.util.Arrays;

/**
 * Created by Weiran Liu on 2017/1/3.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-KP-ABE encryption generator.
 */
public class KPABELLW16EncryptionGenerator extends KPABEHW14EncryptionGenerator {
    private ChameleonHasher chameleonHasher;
    private KPABELLW16PublicKeySerParameter publicKeyParameter;
    private KPABELLW16IntermediateSerParameter intermediate;
    private AsymmetricKeySerParameter chameleonHashPublicKey;
    private AsymmetricKeySerParameter chameleonHashSecretKey;
    private Element C01;
    private Element C02;
    private byte[] chameleonHash;
    private byte[] r;

    public void init(CipherParameters parameter) {
        KPABEEncryptionGenerationParameter oriEncryptionParameter = (KPABEEncryptionGenerationParameter) parameter;
        this.chameleonHasher = oriEncryptionParameter.getChameleonHasher();
        this.publicKeyParameter = (KPABELLW16PublicKeySerParameter) oriEncryptionParameter.getPublicKeyParameter();
        if (oriEncryptionParameter.isIntermediateGeneration()) {
            this.intermediate = (KPABELLW16IntermediateSerParameter)oriEncryptionParameter.getIntermediate();
            this.chameleonHashPublicKey = this.intermediate.getChameleonHashPublicKey();
            this.chameleonHashSecretKey = this.intermediate.getChameleonHashSecretKey();
        } else {
            AsymmetricKeySerPairGenerator chKeyPairGenerator = oriEncryptionParameter.getChameleonHashKeyPairGenerator();
            KeyGenerationParameters chKeyPairGenerationParameter = oriEncryptionParameter.getChameleonHashKeyPairGenerationParameter();
            chKeyPairGenerator.init(chKeyPairGenerationParameter);
            AsymmetricKeySerPair chKeyPair = chKeyPairGenerator.generateKeyPair();
            this.chameleonHashPublicKey = chKeyPair.getPublic();
            this.chameleonHashSecretKey = chKeyPair.getPrivate();
        }
        Pairing pairing = PairingFactory.getPairing(oriEncryptionParameter.getPublicKeyParameter().getParameters());
        String[] attributes = oriEncryptionParameter.getAttributes();
        Element[] mappedElementAttributes = PairingUtils.MapStringArrayToFirstHalfZr(pairing, attributes);
        String[] mappedStringAttributes = PairingUtils.MapElementArrayToStringArray(mappedElementAttributes);
        KPABEEncryptionGenerationParameter resultEncryptionParameter = new KPABEEncryptionGenerationParameter(
                oriEncryptionParameter.getPublicKeyParameter(),
                mappedStringAttributes,
                oriEncryptionParameter.getMessage()
        );
        if (oriEncryptionParameter.isIntermediateGeneration()) {
            KPABEHW14IntermediateSerParameter intermediateHW14 = new KPABEHW14IntermediateSerParameter(
                    this.intermediate.getParameters(),
                    this.intermediate.getN(),
                    this.intermediate.getSessionKey(),
                    this.intermediate.getS(),
                    this.intermediate.getC0(),
                    this.intermediate.getRs(),
                    this.intermediate.getXs(),
                    this.intermediate.getC1s(),
                    this.intermediate.getC2s()
            );
            resultEncryptionParameter.setIntermediate(intermediateHW14);
        }
        super.init(resultEncryptionParameter);
    }

    protected void computeEncapsulation() {
        super.computeEncapsulation();
        try {
            Pairing pairing = PairingFactory.getPairing(this.publicKeyParameter.getParameters());
            if (this.parameter.isIntermediateGeneration()) {
                this.C01 = this.intermediate.getC01().getImmutable();
                this.C02 = this.intermediate.getC02().getImmutable();
                this.chameleonHash = this.intermediate.getChameleonHash();
                this.r = this.intermediate.getR();
            } else {
                Element r0 = pairing.getZr().newRandomElement().getImmutable();
                this.C01 = publicKeyParameter.getG().powZn(r0).getImmutable();
                chameleonHasher.init(false, chameleonHashPublicKey);
                byte[] byteArrayChameleonHashPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
                chameleonHasher.update(byteArrayChameleonHashPublicKey, 0, byteArrayChameleonHashPublicKey.length);
                byte[][] chResult = chameleonHasher.computeHash();
                this.chameleonHash = chResult[0];
                this.r = chResult[1];
                Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
                String mappedStringV = tempV.toString();
                Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
                this.C02 = publicKeyParameter.getU().powZn(V).mul(publicKeyParameter.getH()).powZn(r0).
                        mul(publicKeyParameter.getW().powZn(s.negate())).getImmutable();
            }
            chameleonHasher.init(true, chameleonHashSecretKey);
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
                byte[] byteArrayC3i = C3s.get(attribute).toBytes();
                chameleonHasher.update(byteArrayC3i, 0, byteArrayC3i.length);
            }
            byte[][] chResult = chameleonHasher.findCollision(this.chameleonHash, this.r);
            this.chameleonHash = chResult[0];
            this.r = chResult[1];
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
                new KPABELLW16HeaderSerParameter(
                        publicKeyParameter.getParameters(), chameleonHash, r, chameleonHashPublicKey,
                        C01, C02,  C0, C1s, C2s, C3s)
        );
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new KPABELLW16CiphertextSerParameter(
                publicKeyParameter.getParameters(), chameleonHash, r, chameleonHashPublicKey,
                C01, C02, C, C0, C1s, C2s, C3s);
    }
}

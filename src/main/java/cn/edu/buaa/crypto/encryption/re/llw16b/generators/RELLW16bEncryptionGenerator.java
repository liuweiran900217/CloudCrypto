package cn.edu.buaa.crypto.encryption.re.llw16b.generators;

import cn.edu.buaa.crypto.algebra.generators.AsymmetricKeySerPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.re.genparams.REEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.re.llw16a.generators.RELLW16aEncryptionGenerator;
import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aIntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bIntermediateSerParameter;
import cn.edu.buaa.crypto.encryption.re.llw16b.serparams.RELLW16bPublicKeySerParameter;
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
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE encryption generator.
 */
public class RELLW16bEncryptionGenerator extends RELLW16aEncryptionGenerator {
    private ChameleonHasher chameleonHasher;
    private RELLW16bPublicKeySerParameter publicKeyParameter;
    private RELLW16bIntermediateSerParameter intermediate;
    private AsymmetricKeySerParameter chameleonHashPublicKey;
    private AsymmetricKeySerParameter chameleonHashSecretKey;
    private Element C01;
    private Element C02;
    private byte[] chameleonHash;
    private byte[] r;

    public void init(CipherParameters parameter) {
        REEncryptionGenerationParameter oriEncryptionParameter = (REEncryptionGenerationParameter) parameter;
        this.chameleonHasher = oriEncryptionParameter.getChameleonHasher();
        this.publicKeyParameter = (RELLW16bPublicKeySerParameter) oriEncryptionParameter.getPublicKeyParameter();
        if (oriEncryptionParameter.isIntermediateGeneration()) {
            this.intermediate = (RELLW16bIntermediateSerParameter)oriEncryptionParameter.getIntermediate();
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
        String[] revokeIds = oriEncryptionParameter.getIds();
        Element[] mappedElementIds = PairingUtils.MapStringArrayToFirstHalfZr(pairing, revokeIds);
        String[] mappedStringIds = PairingUtils.MapElementArrayToStringArray(mappedElementIds);
        REEncryptionGenerationParameter resultEncryptionParameter = new REEncryptionGenerationParameter(
                this.publicKeyParameter,
                mappedStringIds,
                oriEncryptionParameter.getMessage()
        );
        if (oriEncryptionParameter.isIntermediateGeneration()) {
            RELLW16aIntermediateSerParameter intermediateLLW16a = new RELLW16aIntermediateSerParameter(
                    this.intermediate.getParameters(),
                    this.intermediate.getN(),
                    this.intermediate.getSessionKey(),
                    this.intermediate.getS(),
                    this.intermediate.getC0(),
                    this.intermediate.getSs(),
                    this.intermediate.getXs(),
                    this.intermediate.getC1s(),
                    this.intermediate.getC2s()
            );
            resultEncryptionParameter.setIntermediate(intermediateLLW16a);
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
                this.C01 = publicKeyParameter.getGb().powZn(r0).getImmutable();
                chameleonHasher.init(false, chameleonHashPublicKey);
                byte[] byteArrayChameleonHashPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
                chameleonHasher.update(byteArrayChameleonHashPublicKey, 0, byteArrayChameleonHashPublicKey.length);
                byte[][] chResult = chameleonHasher.computeHash();
                this.chameleonHash = chResult[0];
                this.r = chResult[1];
                Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
                String mappedStringV = tempV.toString();
                Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
                this.C02 = publicKeyParameter.getGb2().powZn(V).mul(publicKeyParameter.getHb()).powZn(r0).getImmutable();
                this.C0 = this.C0.mul(publicKeyParameter.getG().powZn(r0));
                this.sessionKey = this.sessionKey.mul(publicKeyParameter.getEggAlpha().powZn(r0));
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
            String[] sortedIds = new String[this.parameter.getIds().length];
            System.arraycopy(this.parameter.getIds(), 0, sortedIds, 0, sortedIds.length);
            Arrays.sort(sortedIds);
            for (String id : sortedIds) {
                byte[] byteArrayId = id.getBytes();
                chameleonHasher.update(byteArrayId, 0, byteArrayId.length);
                byte[] byteArrayC1i = C1s.get(id).toBytes();
                chameleonHasher.update(byteArrayC1i, 0, byteArrayC1i.length);
                byte[] byteArrayC2i = C2s.get(id).toBytes();
                chameleonHasher.update(byteArrayC2i, 0, byteArrayC2i.length);
                byte[] byteArrayC3i = C3s.get(id).toBytes();
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
                new RELLW16bHeaderSerParameter(
                        publicKeyParameter.getParameters(), chameleonHash, r, chameleonHashPublicKey,
                        C01, C02,  C0, C1s, C2s, C3s)
        );
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new RELLW16bCiphertextSerParameter(
                publicKeyParameter.getParameters(), chameleonHash, r, chameleonHashPublicKey,
                C01, C02, C, C0, C1s, C2s, C3s);
    }
}

package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.generators;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.chameleonhash.ChameleonHasher;
import cn.edu.buaa.crypto.encryption.abe.cpabe.genparams.CPABEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams.CPABELLW14PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.generators.CPABERW13EncryptionGenerator;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE encryption generator.
 */
public class CPABELLW14EncryptionGenerator extends CPABERW13EncryptionGenerator {
    private ChameleonHasher chameleonHasher;
    private CPABELLW14PublicKeySerParameter publicKeyParameter;
    private Element C01;
    private Element C02;
    private Element C03;
    private byte[] chameleonHash;
    private byte[] r;

    public void init(CipherParameters parameter) {
        CPABEEncryptionGenerationParameter oriEncryptionParameter = (CPABEEncryptionGenerationParameter) parameter;
        this.chameleonHasher = oriEncryptionParameter.getChameleonHasher();
        this.publicKeyParameter = (CPABELLW14PublicKeySerParameter) oriEncryptionParameter.getPublicKeyParameter();

        Pairing pairing = PairingFactory.getPairing(oriEncryptionParameter.getPublicKeyParameter().getParameters());
        String[] rhos = oriEncryptionParameter.getRhos();
        Element[] mappedElementRhos = PairingUtils.MapStringArrayToFirstHalfZr(pairing, rhos);
        String[] mappedStringRhos = PairingUtils.MapElementArrayToStringArray(mappedElementRhos);
        CPABEEncryptionGenerationParameter resultEncryptionParameter = new CPABEEncryptionGenerationParameter(
                oriEncryptionParameter.getAccessControlEngine(),
                oriEncryptionParameter.getPublicKeyParameter(),
                oriEncryptionParameter.getAccessPolicy(),
                mappedStringRhos,
                oriEncryptionParameter.getMessage()
        );
        super.init(resultEncryptionParameter);
    }

    protected void computeEncapsulation() {
        super.computeEncapsulation();
        try {
            Pairing pairing = PairingFactory.getPairing(this.publicKeyParameter.getParameters());
            Element t0 = pairing.getZr().newRandomElement().getImmutable();
            this.C01 = publicKeyParameter.getW().powZn(s).mul(publicKeyParameter.getV().powZn(t0)).getImmutable();
            this.C03 = publicKeyParameter.getG().powZn(t0).getImmutable();
            AsymmetricKeySerParameter chameleonHashPublicKey = publicKeyParameter.getChameleonHashPublicKey();
            chameleonHasher.init(false, chameleonHashPublicKey);
            byte[] byteArrayChPublicKey = PairingUtils.SerCipherParameter(chameleonHashPublicKey);
            chameleonHasher.update(byteArrayChPublicKey, 0, byteArrayChPublicKey.length);
            byte[] byteArrayAccessControlParameter = PairingUtils.SerCipherParameter(accessControlParameter);
            chameleonHasher.update(byteArrayAccessControlParameter, 0, byteArrayAccessControlParameter.length);
            if (this.parameter.getMessage() != null) {
                Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
                byte[] byteArrayC = C.toBytes();
                chameleonHasher.update(byteArrayC, 0, byteArrayC.length);
            }
            byte[] byteArrayC0 = C0.toBytes();
            chameleonHasher.update(byteArrayC0, 0, byteArrayC0.length);
            byte[] byteArrayC01 = C01.toBytes();
            chameleonHasher.update(byteArrayC01, 0, byteArrayC01.length);
            byte[] byteArrayC03 = C03.toBytes();
            chameleonHasher.update(byteArrayC03, 0, byteArrayC03.length);
            for (String rho : accessControlParameter.getRhos()) {
                byte[] byteArrayC1i = C1s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC1i, 0, byteArrayC1i.length);
                byte[] byteArrayC2i = C2s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC2i, 0, byteArrayC2i.length);
                byte[] byteArrayC3i = C3s.get(rho).toBytes();
                chameleonHasher.update(byteArrayC3i, 0, byteArrayC3i.length);
            }
            byte[][] chResult = chameleonHasher.computeHash();
            this.chameleonHash = chResult[0];
            this.r = chResult[1];
            Element tempV = PairingUtils.MapByteArrayToSecondHalfZr(pairing, chResult[0]);
            String mappedStringV = tempV.toString();
            Element V = PairingUtils.MapStringToGroup(pairing, mappedStringV, PairingUtils.PairingGroupType.Zr);
            this.C02 = publicKeyParameter.getU().powZn(V).mul(publicKeyParameter.getH()).powZn(t0.negate()).getImmutable();
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
                new CPABELLW14HeaderSerParameter(publicKeyParameter.getParameters(), chameleonHash, r, C01, C02, C03, C0, C1s, C2s, C3s)
        );
    }

    public PairingCipherSerParameter generateCiphertext() {
        computeEncapsulation();
        Element C = this.sessionKey.mul(this.parameter.getMessage()).getImmutable();
        return new CPABELLW14CiphertextSerParameter(publicKeyParameter.getParameters(),
                chameleonHash, r, C01, C02, C03, C, C0, C1s, C2s, C3s);
    }
}

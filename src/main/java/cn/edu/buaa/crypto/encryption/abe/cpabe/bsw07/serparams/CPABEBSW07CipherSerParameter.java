//package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams;
//
//import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
//import cn.edu.buaa.crypto.utils.PairingUtils;
//import it.unisa.dia.gas.jpbc.Element;
//import it.unisa.dia.gas.jpbc.PairingParameters;
//import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
//
///**
// * Created by Weiran Liu on 2016/11/18.
// *
// * Bethencourt-Sahai-Wtaers large-universe CP-ABE ciphertext parameter.
// */
//public class CPABEBSW07CipherSerParameter extends PairingCipherSerParameter {
//    private transient Element C;
//    private final byte[] byteArrayC;
//
//    private transient Element[] C1s;
//    private final byte[][] byteArraysC1s;
//
//    private transient Element[] C2s;
//    private final byte[][] byteArraysC2s;
//
//    public CPABEBSW07CipherSerParameter(PairingParameters pairingParameters, Element C, Element[] C1s, Element[] C2s) {
//        super(pairingParameters);
//
//        this.C = C.getImmutable();
//        this.byteArrayC = this.C.toBytes();
//
//        this.C1s = ElementUtils.cloneImmutable(C1s);
//        this.byteArraysC1s = PairingUtils.GetElementArrayBytes(this.C1s);
//
//        this.C2s = ElementUtils.cloneImmutable(C2s);
//        this.byteArraysC2s = PairingUtils.GetElementArrayBytes(this.C2s);
//    }
//
//    public Element getC() { return this.C.duplicate(); }
//
//    public Element[] getC1s() { return this.C1s; }
//
//    public Element
//
//    @Override
//    public boolean equals(Object anObject) {
//        if (this == anObject) {
//            return true;
//        }
//        if (anObject instanceof KPABEGPSW06aCipherSerParameter) {
//            KPABEGPSW06aCipherSerParameter that = (KPABEGPSW06aCipherSerParameter)anObject;
//            //Compare Es
//            if (!PairingUtils.isEqualElementArray(this.Es, that.Es)){
//                return false;
//            }
//            if (!PairingUtils.isEqualByteArrays(this.byteArraysEs, that.byteArraysEs)) {
//                return false;
//            }
//            //Compare Pairing Parameters
//            return this.getParameters().toString().equals(that.getParameters().toString());
//        }
//        return false;
//    }
//
//    private void readObject(java.io.ObjectInputStream objectInputStream)
//            throws java.io.IOException, ClassNotFoundException {
//        objectInputStream.defaultReadObject();
//        Pairing pairing = PairingFactory.getPairing(this.getParameters());
//        this.Es = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysEs, PairingUtils.PairingGroupType.G1);
//    }
//}

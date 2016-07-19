package cn.edu.buaa.crypto.access;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

/**
 * Created by Weiran Liu on 2016/7/19.
 */
public interface AccessControlEngine {
    String getEngineName();

    AccessControlParameter generateAccessControl(int[][] accessPolicy, String[] rhos) throws UnsatisfiedAccessControlException;

    Element[] secretSharing(Pairing pairing, Element secret, AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException;

    Element[] reconstructOmegas(Pairing pairing, String[] attributes, AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException;
}

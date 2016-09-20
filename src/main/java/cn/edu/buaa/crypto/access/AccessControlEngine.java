package cn.edu.buaa.crypto.access;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/19.
 *
 * Access Control Engine interface, all access control instance should implement this interface.
 */
public interface AccessControlEngine {
    String getEngineName();

    boolean isSupportThresholdGate();

    AccessControlParameter generateAccessControl(int[][] accessPolicy, String[] rhos);

    Map<String, Element> secretSharing(Pairing pairing, Element secret, AccessControlParameter accessControlParameter);

    Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes, AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException;
}

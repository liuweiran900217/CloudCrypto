package com.example.access.tree;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.tree.AccessTreeEngine;
import com.example.access.AccessControlEngineTest;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/20.
 */
public class AccessTreeEngineTest {
    public static void main(String[] args) {
        AccessControlEngineTest accessTreeEngineTest = new AccessControlEngineTest(AccessTreeEngine.getInstance());
        accessTreeEngineTest.testAccessPolicy();
    }
}

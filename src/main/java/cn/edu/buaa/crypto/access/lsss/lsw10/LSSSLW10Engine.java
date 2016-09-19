package cn.edu.buaa.crypto.access.lsss.lsw10;

import Jama.Matrix;
import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.AccessTreeNode;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.lsss.LSSSPolicyEngine;
import cn.edu.buaa.crypto.access.lsss.LSSSPolicyParameter;
import cn.edu.buaa.crypto.access.parser.BinaryTreeNode;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/20.
 *
 * This is the implementation of the linear secret sharing scheme proposed by Lewko and Waters in 2010.
 * Conference version: A. Lewko, B. Waters. Decentralizing attribute-based encryption. EUROCRYPT 2011, 568-588.
 * Full version: A. Lewko, B. Waters. Decentralizing attribute-based encryption. IACR Cryptology ePrint Achieve, 351, 2010.
 *
 * The original version of this code is written by the colleague of Cong Li,
 * which can be downloaded at https://github.com/cleverli2008/ABE.
 * I rewrite the code to meet my code architecture.
 */
public class LSSSLW10Engine extends LSSSPolicyEngine {
    public static String SCHEME_NAME = "Lewko-Waters-11 Linear Secret Sharing Scheme";

    private static LSSSLW10Engine instance = new LSSSLW10Engine();

    private LSSSLW10Engine() {

    }

    public static LSSSLW10Engine getInstance() {
        return instance;
    }

    public String getEngineName() {
        return this.SCHEME_NAME;
    }

    public boolean isSupportThresholdGate() {
        return false;
    }

    public AccessControlParameter generateAccessControl(int[][] accessPolicy, String[] rhos) throws UnsatisfiedAccessControlException {
        //init access tree
        AccessTreeNode rootAccessTreeNode = AccessTreeNode.GenerateAccessTree(accessPolicy, rhos);
        //reconstruct binary tree node
        BinaryTreeNode rootBinaryTreeNode = BinaryTreeNode.ReconstructBinaryTreeNode(accessPolicy, rhos);

        //generate lsss matrix
        Map<String, LinkedList<LinkedList<Integer>>> map = new LinkedHashMap<String, LinkedList<LinkedList<Integer>>>();
        int maxLen = 0;
        int rows = 0;
        //We maintain a global counter variable c, which is initialized to 1.
        int c = 1;
        LinkedList<Integer> vector = new LinkedList<Integer>();
        //We begin by labeling the root node of the tree with the vector (1) (a vector of length 1).
        vector.add(1);
        rootBinaryTreeNode.setVector(vector);

        LinkedList<BinaryTreeNode> queue = new LinkedList<BinaryTreeNode>();
        queue.add(rootBinaryTreeNode);

        while (!queue.isEmpty()) {
            BinaryTreeNode p = queue.removeFirst();
            if (p.getType() == BinaryTreeNode.NodeType.AND) {
                //If the parent node is and AND gate labeled by the vector v
                int size = p.getVector().size();
                LinkedList<Integer> pv = new LinkedList<Integer>();
                //we pad v with 0's at the end (if necessary) to make it of length c.
                if (size < c) {
                    pv.addAll(p.getVector());
                    for (int i = 0; i < c - size; i++) {
                        pv.add(0);
                    }
                } else {
                    pv.addAll(p.getVector());
                }
                //Then we label one of its children (right children) with the vector v|1
                BinaryTreeNode right = p.getRight();
                LinkedList<Integer> lv = new LinkedList<Integer>();
                lv.addAll(pv);
                lv.addLast(1);
                right.setVector(lv);
                queue.add(right);

                //Then we label one of its children (left children) with the vector (0,...,0)|-1
                BinaryTreeNode left = p.getLeft();
                LinkedList<Integer> rv = new LinkedList<Integer>();
                for (int i = 0; i < c; i++) {
                    rv.add(0);
                }
                rv.addLast(-1);
                left.setVector(rv);
                queue.add(left);
                //We now increment the value of c by 1.
                c += 1;
            } else if (p.getType() == BinaryTreeNode.NodeType.OR) {
                //If the parent node is an OR gate labeled by the vector v
                BinaryTreeNode left = p.getLeft();
                LinkedList<Integer> lv = new LinkedList<Integer>();
                //then we also label its (left) children by v (and the value of c stays the same)
                lv.addAll(p.getVector());
                left.setVector(lv);
                queue.add(left);

                BinaryTreeNode right = p.getRight();
                LinkedList<Integer> rv = new LinkedList<Integer>();
                //then we also label its (right) children by v (and the value of c stays the same)
                rv.addAll(p.getVector());
                right.setVector(rv);
                queue.add(right);
            } else {
                // leaf node
                rows += 1;
                int size = p.getVector().size();
                maxLen = size > maxLen ? size : maxLen;
                if (map.containsKey(p.getValue())) {
                    map.get(p.getValue()).add(p.getVector());
                } else {
                    LinkedList<LinkedList<Integer>> list = new LinkedList<LinkedList<Integer>>();
                    list.add(p.getVector());
                    map.put(p.getValue(), list);
                }
            }
        }

        for (Map.Entry<String, LinkedList<LinkedList<Integer>>> entry : map
                .entrySet()) {
            LinkedList<LinkedList<Integer>> v = entry.getValue();
            for (int i = 0; i < v.size(); i++) {
                int size = v.get(i).size();
                if (size < maxLen) {
                    for (int j = 0; j < maxLen - size; j++) {
                        v.get(i).add(0);
                    }
                }
            }
        }

        //construct the lsss Matrix
        int[][] lsssMatrix = new int[rows][];
        String[] rhosParameter = new String[rhos.length];
        int i = 0;
        for (Map.Entry<String, LinkedList<LinkedList<Integer>>> entry : map.entrySet()) {
            LinkedList<LinkedList<Integer>> v = entry.getValue();
            for (int j = 0; j < v.size(); j++) {
                rhosParameter[i] = entry.getKey();
                lsssMatrix[i] = new int[maxLen];
                for(int k = 0; k < maxLen; k++){
                    lsssMatrix[i][k] = v.get(j).get(k);
                }
                i += 1;
            }
        }
        LSSSPolicyParameter lsssPolicyParameter = new LSSSPolicyParameter(rootAccessTreeNode, accessPolicy, lsssMatrix, rhosParameter);
//        System.out.println(lsssPolicyParameter);
        return lsssPolicyParameter;
    }
}

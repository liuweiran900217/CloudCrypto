package cn.edu.buaa.crypto.access.lsss.lsw10;

import Jama.Matrix;
import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.AccessTreeNode;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
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
 */
public class LSSSLW10Engine implements AccessControlEngine {
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
        int c = 1;
        LinkedList<Integer> vector = new LinkedList<Integer>();
        vector.add(1);
        rootBinaryTreeNode.setVector(vector);

        LinkedList<BinaryTreeNode> queue = new LinkedList<BinaryTreeNode>();
        queue.add(rootBinaryTreeNode);

        while (!queue.isEmpty()) {
            BinaryTreeNode p = queue.removeFirst();
            if (p.getType() == BinaryTreeNode.NodeType.AND) {
                int size = p.getVector().size();
                LinkedList<Integer> pv = new LinkedList<Integer>();
                if (size < c) {
                    pv.addAll(p.getVector());
                    for (int i = 0; i < c - size; i++) {
                        pv.add(0);
                    }
                } else {
                    pv.addAll(p.getVector());
                }

                BinaryTreeNode right = p.getRight();
                LinkedList<Integer> lv = new LinkedList<Integer>();
                lv.addAll(pv);
                lv.addLast(1);
                right.setVector(lv);
                queue.add(right);

                BinaryTreeNode left = p.getLeft();
                LinkedList<Integer> rv = new LinkedList<Integer>();
                for (int i = 0; i < c; i++) {
                    rv.add(0);
                }
                rv.addLast(-1);
                left.setVector(rv);
                queue.add(left);

                c += 1;
            } else if (p.getType() == BinaryTreeNode.NodeType.OR) {
                BinaryTreeNode left = p.getLeft();
                LinkedList<Integer> lv = new LinkedList<Integer>();
                lv.addAll(p.getVector());
                left.setVector(lv);
                queue.add(left);

                BinaryTreeNode right = p.getRight();
                LinkedList<Integer> rv = new LinkedList<Integer>();
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
        LSSSPolicyParameter lsssPolicyParameter = new LSSSPolicyParameter(rootAccessTreeNode, lsssMatrix, rhosParameter);
//        System.out.println(lsssPolicyParameter);
        return lsssPolicyParameter;
    }

    public Map<String, Element> secretSharing(Pairing pairing, Element secret, AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException {
        if (!(accessControlParameter instanceof LSSSPolicyParameter)) {
            throw new UnsatisfiedAccessControlException("Invalid LSSSPolicy Parameter, find " + accessControlParameter.getClass().getName());
        }
        LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter)accessControlParameter;
        int row = lsssPolicyParameter.getRow();
        int column = lsssPolicyParameter.getColumn();
        int[][] lsssMatrix = lsssPolicyParameter.getLSSSMatrix();
        Element[][] elementLSSSMatrix = new Element[row][column];
        for (int i = 0; i < lsssPolicyParameter.getRow(); i++) {
            for (int j = 0; j < lsssPolicyParameter.getColumn(); j++) {
                elementLSSSMatrix[i][j] = pairing.getZr().newElement(lsssMatrix[i][j]).getImmutable();
            }
        }
        //init vector v
        Element[] elementsV = new Element[column];
        elementsV[0] = secret.duplicate().getImmutable();
        for (int i = 1; i < elementsV.length; i++) {
            elementsV[i] = pairing.getZr().newRandomElement().getImmutable();
        }
        //secret share by matrix multiplication
        Map<String, Element> lambdaElementsMap = new HashMap<String, Element>();
        for (int i=0; i<row; i++) {
            Element elementsLambda = pairing.getZr().newZeroElement().getImmutable();
            for (int j=0; j<column; j++) {
                elementsLambda = elementsLambda.add(elementLSSSMatrix[i][j].mulZn(elementsV[j])).getImmutable();
            }
            lambdaElementsMap.put(lsssPolicyParameter.getRhos()[i], elementsLambda);
        }
        return lambdaElementsMap;
    }

    public Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes, AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException {
        if (!(accessControlParameter instanceof LSSSPolicyParameter)) {
            throw new UnsatisfiedAccessControlException("Invalid LSSSPolicy Parameter, find " + accessControlParameter.getClass().getName());
        }
        LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter)accessControlParameter;
        int[] result;
        String[] minSatisfiedAttributes = lsssPolicyParameter.minSatisfiedAttributeSet(attributes);
        String[] leafAttributes = lsssPolicyParameter.getRhos();
        int[] rows = new int[minSatisfiedAttributes.length];
        int counter = 0;
        for(int i = 0; i < leafAttributes.length; i++){
            for(int j = 0; j < minSatisfiedAttributes.length; j++){
                if(leafAttributes[i].equals(minSatisfiedAttributes[j])) {
                    //比较L矩阵和获得的S参数中各个元素，记下所有相同的元素对应的在数组中的位置，并生成一个新的矩阵，把相同的元素存在一个叫做result的数组之中，长度为counter
                    rows[counter++] = i;
                }
            }
        }
        result = new int[counter];
        System.arraycopy(rows, 0, result, 0, counter);
        //filter M to rows from all zero cols and transpose it
        //eliminate all zero cols
        counter = 0;
        int [] cols = new int[result.length];
        for(int j = 0; j < lsssPolicyParameter.getColumn(); j++){
            for(int i = 0; i < result.length; i++){
                if(lsssPolicyParameter.getLSSSMatrix()[result[i]][j] != 0) {
                    if(counter == cols.length){
                        //此时矩阵不满足解密的条件
                        throw new UnsatisfiedAccessControlException("Invalid access structure or attributes. Unable to reconstruct coefficients.");
                    }
                    //把不都为0的列数调出来，把列数j存到叫做的cols的数组之中,此时counter的含义是代表了新生成的M矩阵的列数
                    cols[counter++] = j;
                    break;
                }
            }
        }
        double[][] Mreduced = new double[counter][counter];
        for(int i = 0; i < result.length; i++){
            for(int j = 0; j < result.length; j++){
                //将原本M矩阵中的满足attributes条件的以及不都为0的列的条件的元素填到一个新的矩阵中，称为Mreduced，该矩阵事宜个长宽均为result.length的方阵
                Mreduced[j][i] = lsssPolicyParameter.getLSSSMatrix()[result[j]][cols[i]];
            }
        }
        //solve the linear system
        Matrix mA = new Matrix(Mreduced);
        mA = mA.inverse();
        double[] _b = get_identity_vector(mA.getColumnDimension());
        Matrix mb = new Matrix(_b, 1);
        Matrix res = mb.times(mA);
        double[] solution = res.getRowPackedCopy();

        Element[] minSatisfiedOmegaElements = new Element[solution.length];
        for (int i = 0; i < minSatisfiedOmegaElements.length; i++) {
            minSatisfiedOmegaElements[i] = pairing.getZr().newElement(pairing.getZr().newElement((int) solution[i])).getImmutable();
        }

        Map<String, Element> omegaElementsMap = new HashMap<String, Element>();
        for (int i = 0; i < rows.length; i++) {
            for (int j = 0; j < attributes.length; j++) {
                if (leafAttributes[rows[i]].equals(attributes[j])) {
                    omegaElementsMap.put(attributes[j], minSatisfiedOmegaElements[i].duplicate().getImmutable());
                }
            }
        }
        for (int i = 0; i < attributes.length; i++) {
            if (!omegaElementsMap.containsKey(attributes[i])) {
                omegaElementsMap.put(attributes[i], pairing.getZr().newZeroElement().getImmutable());
            }
        }
        return omegaElementsMap;
    }

    private double[] get_identity_vector(int length) {
        ;//该方法实现的功能是：生成矩阵求逆时等号右边的列向量，第一个数为1，剩下的都是0
        double[] result = new double[length];
        result[0] = 1.0;
        for(int i = 1; i < length; i++) {
            result[i] = 0.0;
        }
        return result;
    }
}

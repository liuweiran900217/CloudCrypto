//package cn.edu.buaa.crypto.access.lsss.lcw10;
//
///**
// * This is the implementation of linear secret sharing is based on the algorithm of Liu et al <br>
// * See http://eprint.iacr.org/2010/374 <br>
// * We adapted the miracl version of the implementation <br>
// * https://certivox.jira.com/wiki/display/MIRACLPUBLIC/Home
// *
// * An access structure is represented using as an int[][] array
// * with row indexes being the node ids and each row describes a node (k of n threshold and list of children nodes or leafs).
// * A leaf node has a negative index <br>
// * Example: from the paper See http://eprint.iacr.org/2010/374<br>
// * int access[][]={
// *	{2,2,1,2}, //the root node 0 is a 2of2 threshold and its children are nodes 1 and 2 (at rows 1 and 2) <br>
// *	{2,1,3,4}, //node 1 is a 1of2 threshold and its children are nodes 3 and 4 <br>
// *	{4,3,-5,-6,-7,-8}, //node 2 note that -5 here correponds to index of attribute E in the alphabet<br>
// *	{2,2,-2,5}, //node 3<br>
// *	{3,2,-3,-4,-5}, //node 4 <br>
// *	{2,1,-1,-3} //node 5 <br>
// *	}; <br>
// * The number of rows in the LSSS matrix equal to the number of leaves <br>
// * The number of cols is 1+sum_i(t_i -1) where t_i is the threshold of non leaf nodes i
// *
// * Notice that it is easy to retrieve the children of a node in order.
// * We use this structure to avoid having to construct/traverse trees especially
// * since the parent realtion is not needed in the LSSS construction algorithm <br>
// *
// * Objects are immutable
// * @author jkhoury
// *
// */
//
//import Jama.Matrix;
//import cn.edu.buaa.crypto.access.AccessControlEngine;
//import cn.edu.buaa.crypto.access.AccessControlParameter;
//import cn.edu.buaa.crypto.access.AccessTreeNode;
//import cn.edu.buaa.crypto.access.lsss.LSSSPolicyEngine;
//import cn.edu.buaa.crypto.access.lsss.LSSSPolicyParameter;
//import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
//import it.unisa.dia.gas.jpbc.Element;
//import it.unisa.dia.gas.jpbc.Pairing;
//
//import java.util.HashMap;
//import java.util.Map;
//
//public class LSSSLCW10Engine extends LSSSPolicyEngine {
//    public static String SCHEME_NAME = "LCW10 Linear Secret Sharing Scheme";
//
//    private static LSSSLCW10Engine instance = new LSSSLCW10Engine();
//
//    private LSSSLCW10Engine() {
//
//    }
//
//    public static LSSSLCW10Engine getInstance() {
//        return instance;
//    }
//
//    public String getEngineName() {
//        return this.SCHEME_NAME;
//    }
//
//    public boolean isSupportThresholdGate() {
//        return true;
//    }
//
//    public LSSSPolicyParameter generateAccessControl(final int[][] accessPolicy, final String[] rhos) throws UnsatisfiedAccessControlException {
//        //init access tree
//        AccessTreeNode rootAccessTreeNode = AccessTreeNode.GenerateAccessTree(accessPolicy, rhos);
//        //init row, column, and lessMatrix
//        int rowParameter = 0;
//        int columnParameter = 1;
//        for(int i = 0; i < accessPolicy.length; i++){
//            //每个数组的第二个元素是门限值t，总的列数就是门限值的总和，但是每次累加要减1是因为数组的开始元素是0
//            columnParameter += (accessPolicy[i][1] - 1);
//            for(int j = 2; j < accessPolicy[i].length; j++){
//                //从每个数组的而第三个元素开始就表示的节点的编号了，只要是负数，就以为着这是一个叶子节点，那么最后的行数就是叶子节点的数目
//                if(accessPolicy[i][j] < 0){
//                    rowParameter++;
//                }
//            }
//        }
//        if (rhos.length != rowParameter) {
//            //Invalid access policy, same attribute exist in multiple leaf nodes.
//            throw new UnsatisfiedAccessControlException("Invalid access policy, number of leaf nodes " + rowParameter
//                    + " does not match number of rhos " + rhos.length);
//        }
//        //将获得的行数和列数赋给M和L，将M矩阵各个元素赋值为0，并对L矩阵中的每一个数赋值为-1
//        int[][] lsssMatrix = new int[rowParameter][columnParameter];
//        int[] leafIndex = new int[rowParameter];
//        for(int i = 0; i < rowParameter; i++){
//            for(int j = 0; j < columnParameter; j++){
//                lsssMatrix[i][j] = 0;
//            }
//            leafIndex[i] = -1;
//        }
//
//        /* Start to Generate LSSS Matrix */
//        //initially just has the root node
//        leafIndex[0] = 0;
//        lsssMatrix[0][0] = 1;
//        boolean hasMorework = true;
//        int z = 0;
//        int m2 = 0;
//        int d2 = 0;
//        int m = 1;
//        int d = 1;
//        int k = 0;
//        int node = 0;
//
//        while(hasMorework){
//            node = leafIndex[z];
//            m2 = accessPolicy[node][0]; //children
//            d2 = accessPolicy[node][1]; //threshold
//            //shift cells down in both L and M
//            for (int i = m - 1; i > z; i--){
//                leafIndex[i + (m2 - 1)] = leafIndex[i];
//                System.arraycopy(lsssMatrix[i], 0, lsssMatrix[i + (m2 - 1)], 0, d);
//            }
//            //fill in shifted cells
//            for(int i = 0; i < m2; i++){
//                leafIndex[i + z] = accessPolicy[node][i + 2];
//                System.arraycopy(lsssMatrix[z], 0, lsssMatrix[i + z], 0, d);
//                k = 1;
//                for(int j = d; j< d + (d2 - 1); j++){
//                    k *= (i + 1);
//                    lsssMatrix[i + z][j] = k;
//                }
//            }
//            m += (m2 - 1);
//            d += (d2 - 1);
//            //are we done?
//            z = -1;
//            for(int i = 0; i <rowParameter; i++){
//                if(leafIndex[i] >= 0){ //not a leaf/attribute
//                    z = i;
//                    break;
//                }
//            }
//            if(z < 0) {
//                hasMorework = false;
//            }
//        }
//        //start indexing at 0 to Alphabet - 1
//        for(int i = 0; i < rowParameter; i++) {
//            leafIndex[i] = -leafIndex[i] - 1;
//        }
//        //Check if multiple leaf node have same index
//        boolean[] haveDistinctLeafNodes = new boolean[rowParameter];
//        for (int i = 0; i < leafIndex.length; i++) {
//            haveDistinctLeafNodes[leafIndex[i]] = true;
//        }
//        for (int i = 0; i < haveDistinctLeafNodes.length; i++) {
//            if (!haveDistinctLeafNodes[i]) {
//                throw new UnsatisfiedAccessControlException("Invalid access policy, same attribute exist in multiple leaf nodes.");
//            }
//        }
//        //init rho map
//        String[] rhosParameter = new String[rowParameter];
//        for (int i = 0; i<leafIndex.length; i++) {
//            rhosParameter[i] = new String(rhos[leafIndex[i]]);
//        }
//        return new LSSSPolicyParameter(rootAccessTreeNode, lsssMatrix, rhosParameter);
//    }
//}

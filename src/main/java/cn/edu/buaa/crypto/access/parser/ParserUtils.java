package cn.edu.buaa.crypto.access.parser;

import cn.edu.buaa.crypto.access.lsss.LSSSPolicyParameter;

import java.util.ArrayList;
import java.util.LinkedList;

/**
 * Created by Weiran Liu on 2016/7/20.
 */
public class ParserUtils {
    private static char SPACE = ' ';

    private static String StringPolicyFormat(String policy) {
        policy = policy.trim();
        policy = policy.replaceAll("\\(", "(" + ParserUtils.SPACE);
        policy = policy.replaceAll("\\)", ParserUtils.SPACE + ")");
        return policy;
    }

    public static int[][] GenerateAccessPolicy(String policy) throws PolicySyntaxException {
        String formattedPolicy = StringPolicyFormat(policy);
        BinaryTreeNode rootBinaryTreeNode = new PolicyParser().parse(formattedPolicy);
        BinaryTreeNode.updateParentPointer(rootBinaryTreeNode);

        LinkedList<int[]> accessPolicyLinkedList = new LinkedList<int[]>();
        //convert to int[][] accessPolicy
        LinkedList<BinaryTreeNode> queue = new LinkedList<BinaryTreeNode>();
        queue.add(rootBinaryTreeNode);

        int nextNodeLabel = 0;
        int nextLeafNodeLabel = 1;
        int labelLeft = 0;
        int labelRight = 0;
        while (!queue.isEmpty()) {
            BinaryTreeNode p = queue.removeFirst();
            if (p.getType() == BinaryTreeNode.NodeType.LEAF) {
                continue;
            } else {
                if (p.getLeft().getType() == BinaryTreeNode.NodeType.LEAF) {
                    labelLeft = -1 * nextLeafNodeLabel;
                    nextLeafNodeLabel++;
                } else {
                    labelLeft = ++nextNodeLabel;
                }
                if (p.getRight().getType() == BinaryTreeNode.NodeType.LEAF) {
                    labelRight = -1 * nextLeafNodeLabel;
                    nextLeafNodeLabel++;
                } else {
                    labelRight = ++nextNodeLabel;
                }
                queue.add(p.getLeft());
                queue.add(p.getRight());
                if (p.getType() == BinaryTreeNode.NodeType.AND) {
                    accessPolicyLinkedList.add(new int[] {2, 2, labelLeft, labelRight});
                } else {
                    accessPolicyLinkedList.add(new int[] {2, 1, labelLeft, labelRight});
                }
            }
        }
        int[][] accessPolicy = new int[accessPolicyLinkedList.size()][];
        for (int i = 0; i < accessPolicyLinkedList.size(); i++) {
            accessPolicy[i] = accessPolicyLinkedList.get(i);
        }
        return accessPolicy;
    }

    public static String[] GenerateRhos(String policy) throws PolicySyntaxException {
        String formattedPolicy = StringPolicyFormat(policy);
        BinaryTreeNode rootBinaryTreeNode = new PolicyParser().parse(formattedPolicy);
        BinaryTreeNode.updateParentPointer(rootBinaryTreeNode);

        ArrayList<String> rhosArrayList = new ArrayList<String>();
        LinkedList<BinaryTreeNode> queue = new LinkedList<BinaryTreeNode>();
        queue.add(rootBinaryTreeNode);
        while (!queue.isEmpty()) {
            BinaryTreeNode p = queue.removeFirst();
            if (p.getType() == BinaryTreeNode.NodeType.LEAF) {
                rhosArrayList.add(p.getValue());
            } else {
                queue.add(p.getLeft());
                queue.add(p.getRight());
            }
        }
        String[] rhos = new String[rhosArrayList.size()];
        for (int i = 0; i < rhos.length; i++) {
            rhos[i] = rhosArrayList.get(i);
        }
        return rhos;
    }
}

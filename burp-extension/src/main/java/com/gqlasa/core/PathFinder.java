package com.gqlasa.core;

import com.gqlasa.core.schema.*;
import com.gqlasa.util.Strings;

import java.util.*;

public final class PathFinder {
    private PathFinder(){}

    public static class Segment {
        public String parentType;
        public String fieldName;
        public String fieldReturnType;
        public boolean hasRequiredArgs;

        public Segment(String parentType, String fieldName, String fieldReturnType, boolean hasRequiredArgs) {
            this.parentType = parentType;
            this.fieldName = fieldName;
            this.fieldReturnType = fieldReturnType;
            this.hasRequiredArgs = hasRequiredArgs;
        }
    }

    /**
     * Finds all distinct (acyclic-by-type) paths from Query root fields to a target type.
     * Prevents path explosion caused by type cycles (A -> B -> A ...).
     */
    public static List<List<Segment>> findAllPaths(SchemaIndex schema, String targetType, int maxDepth) {
        if (schema == null) throw new IllegalArgumentException("Schema is null.");
        if (Strings.isBlank(schema.queryTypeName)) throw new IllegalArgumentException("Schema has no queryType name.");
        if (Strings.isBlank(targetType)) throw new IllegalArgumentException("Target type is empty.");
        if (!schema.types.containsKey(targetType)) {
            throw new IllegalArgumentException("Target type '" + targetType + "' does not exist in the schema.");
        }

        GqlTypeDef query = schema.types.get(schema.queryTypeName);
        if (query == null) throw new IllegalArgumentException("Query type definition not found: " + schema.queryTypeName);

        List<List<Segment>> results = new ArrayList<>();

        for (GqlField rootField : query.fields) {
            String nextType = rootField.type == null ? null : rootField.type.unwrapName();
            if (Strings.isBlank(nextType)) continue;

            Segment rootSeg = new Segment(schema.queryTypeName, rootField.name, nextType, rootField.hasRequiredArgs());

            if (targetType.equals(nextType)) {
                results.add(Collections.singletonList(rootSeg));
                continue;
            }

            Deque<Segment> stack = new ArrayDeque<>();
            stack.add(rootSeg);

            Set<String> visitedTypes = new HashSet<>();
            visitedTypes.add(schema.queryTypeName);
            visitedTypes.add(nextType);

            dfs(schema, targetType, nextType, maxDepth, results, stack, visitedTypes);
        }

        return results;
    }

    private static void dfs(SchemaIndex schema, String targetType, String currentType, int maxDepth,
                            List<List<Segment>> results, Deque<Segment> path, Set<String> visitedTypes) {
        if (path.size() >= maxDepth) return;

        GqlTypeDef def = schema.types.get(currentType);
        if (def == null) return;
        if (!"OBJECT".equals(def.kind) && !"INTERFACE".equals(def.kind)) return;

        for (GqlField f : def.fields) {
            String next = f.type == null ? null : f.type.unwrapName();
            if (Strings.isBlank(next)) continue;

            if (visitedTypes.contains(next)) continue;

            Segment seg = new Segment(currentType, f.name, next, f.hasRequiredArgs());
            path.addLast(seg);
            visitedTypes.add(next);

            if (targetType.equals(next)) {
                results.add(new ArrayList<>(path));
            } else {
                dfs(schema, targetType, next, maxDepth, results, path, visitedTypes);
            }

            visitedTypes.remove(next);
            path.removeLast();
        }
    }

    public static String formatPathText(List<Segment> segments) {
        if (segments.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        Segment root = segments.get(0);
        sb.append("Query (").append(root.fieldName).append(") -> ").append(root.fieldReturnType);
        for (int i = 1; i < segments.size(); i++) {
            Segment s = segments.get(i);
            sb.append(" (").append(s.fieldName).append(") -> ").append(s.fieldReturnType);
        }
        return sb.toString();
    }
}

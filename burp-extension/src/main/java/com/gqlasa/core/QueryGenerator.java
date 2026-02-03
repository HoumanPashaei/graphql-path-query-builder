package com.gqlasa.core;

import com.gqlasa.core.PathFinder.Segment;
import com.gqlasa.core.schema.*;
import com.gqlasa.model.BuiltQuery;
import com.gqlasa.util.Strings;

import java.util.*;

public final class QueryGenerator {
    private QueryGenerator(){}

    public static BuiltQuery buildQuery(SchemaIndex schema, String targetType, List<Segment> path,
                                        int opIndex, int maxSelectionDepth, boolean includeRequiredArgs) {
        String opName = "op_" + targetType + "_" + opIndex;
        StringBuilder sb = new StringBuilder();
        Map<String, Object> variables = new LinkedHashMap<>();
        List<String> varDefs = new ArrayList<>();

        Segment root = path.get(0);
        String rootField = root.fieldName;

        String rootArgs = "";
        if (includeRequiredArgs) {
            GqlTypeDef query = schema.types.get(schema.queryTypeName);
            GqlField rf = findField(query, rootField);
            if (rf != null && rf.args != null) {
                List<String> argUses = new ArrayList<>();
                for (GqlInputValue a : rf.args) {
                    if (a == null || a.type == null) continue;
                    if (!a.isRequired()) continue;
                    String varName = "Query_" + rootField + "_" + a.name;
                    varDefs.add("$" + varName + ": " + a.type.renderTypeSDL());
                    argUses.add(a.name + ": $" + varName);
                    variables.put(varName, "REPLACE_ME");
                }
                if (!argUses.isEmpty()) rootArgs = "(" + String.join(", ", argUses) + ")";
            }
        }

        sb.append("query ").append(opName);
        if (!varDefs.isEmpty()) sb.append("(").append(String.join(", ", varDefs)).append(")");
        sb.append(" {\n");

        int indent = 4;
        sb.append(spaces(indent)).append(rootField).append(rootArgs).append(" {\n");

        for (int i = 1; i < path.size(); i++) {
            Segment seg = path.get(i);
            indent += 4;
            sb.append(spaces(indent)).append(seg.fieldName).append(" {\n");
        }

        indent += 4;
        sb.append(buildSelectionSet(schema, targetType, maxSelectionDepth, indent, new HashSet<>()));

        for (int i = path.size(); i >= 1; i--) {
            indent -= 4;
            sb.append(spaces(indent)).append("}\n");
        }
        sb.append("}\n");

        return new BuiltQuery(opName, sb.toString(), variables);
    }

    private static String buildSelectionSet(SchemaIndex schema, String typeName, int maxDepth, int indent, Set<String> visitedTypes) {
        if (maxDepth <= 0 || visitedTypes.contains(typeName)) return spaces(indent) + "__typename\n";
        visitedTypes.add(typeName);

        GqlTypeDef def = schema.types.get(typeName);
        if (def == null) return spaces(indent) + "__typename\n";

        StringBuilder sb = new StringBuilder();
        sb.append(spaces(indent)).append("__typename\n");

        if (!"OBJECT".equals(def.kind) && !"INTERFACE".equals(def.kind)) return sb.toString();

        for (GqlField f : def.fields) {
            if (f == null || Strings.isBlank(f.name) || f.type == null) continue;
            String k = f.type.unwrapKind();
            String n = f.type.unwrapName();
            if (Strings.isBlank(k) || Strings.isBlank(n)) continue;

            if ("SCALAR".equals(k) || "ENUM".equals(k)) {
                sb.append(spaces(indent)).append(f.name).append("\n");
            } else if ("OBJECT".equals(k) || "INTERFACE".equals(k) || "UNION".equals(k)) {
                sb.append(spaces(indent)).append(f.name).append(" {\n");
                sb.append(buildSelectionSet(schema, n, maxDepth - 1, indent + 4, visitedTypes));
                sb.append(spaces(indent)).append("}\n");
            } else {
                sb.append(spaces(indent)).append(f.name).append("\n");
            }
        }

        visitedTypes.remove(typeName);
        return sb.toString();
    }

    private static GqlField findField(GqlTypeDef def, String name) {
        if (def == null || def.fields == null) return null;
        for (GqlField f : def.fields) if (f != null && name.equals(f.name)) return f;
        return null;
    }

    private static String spaces(int n) { return " ".repeat(Math.max(0, n)); }
}

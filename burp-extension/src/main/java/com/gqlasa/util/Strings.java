package com.gqlasa.util;

public final class Strings {
    private Strings() {}

    public static String nullToEmpty(String s) { return s == null ? "" : s; }

    public static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }
}

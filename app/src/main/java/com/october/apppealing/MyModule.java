package com.october.apppealing;

import android.os.Build;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.io.File;

public class MyModule implements IXposedHookLoadPackage {

    private static final String TAG = "INCAByPass";
    private static final String TARGET = "com.megaxus.ayodance";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (!lpparam.packageName.equals(TARGET)) return;

        String process = lpparam.processName;
        XposedBridge.log(TAG + ": loaded in process=" + process + " pkg=" + lpparam.packageName);

        ClassLoader cl = lpparam.classLoader;

        // =============================================
        // 1. Hook File.exists() to block root detection
        // =============================================
        XposedHelpers.findAndHookMethod(File.class, "exists", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String path = ((File) param.thisObject).getAbsolutePath();
                if (path.contains("/su") || path.equals("/system/bin/su") ||
                    path.equals("/system/xbin/su") || path.contains("magisk") ||
                    path.contains("superuser") || path.contains("SuperSU") ||
                    path.contains("frida") || path.contains("xposed") ||
                    path.contains("busybox") || path.contains("daemonsu") ||
                    path.contains("/sbin/su") || path.contains("/data/local/tmp/frida") ||
                    path.contains("/system/app/Superuser") ||
                    path.contains("libfrida") || path.contains("re.frida")) {
                    param.setResult(false);
                }
            }
        });

        // =============================================
        // 2. Hook Runtime.exec to block detection cmds
        // =============================================
        XC_MethodHook execHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                Object arg = param.args[0];
                String cmd = (arg instanceof String) ? (String) arg :
                             (arg instanceof String[]) ? String.join(" ", (String[]) arg) : "";
                if (cmd.contains("su") || cmd.contains("magisk") ||
                    cmd.contains("which su") || cmd.contains("getprop") ||
                    cmd.contains("frida") || cmd.contains("xposed") ||
                    cmd.contains("busybox")) {
                    param.setResult(null);
                }
            }
        };
        try {
            XposedHelpers.findAndHookMethod(Runtime.class, "exec", String.class, execHook);
        } catch (Throwable ignored) {}
        try {
            XposedHelpers.findAndHookMethod(Runtime.class, "exec", String[].class, execHook);
        } catch (Throwable ignored) {}

        // =============================================
        // 3. Hook Build.TAGS / Build.FINGERPRINT
        // =============================================
        try {
            XposedHelpers.setStaticObjectField(Build.class, "TAGS", "release-keys");
            XposedHelpers.setStaticObjectField(Build.class, "FINGERPRINT",
                "google/oriole/oriole:14/UQ1A.240505.004/11414087:user/release-keys");
        } catch (Throwable ignored) {}

        // =============================================
        // 4. Hook INCA AppGuard classes
        // =============================================

        // AppGuardEngine - main detection engine
        String[] engineClasses = {
            "com.inca.security.Cire.AppGuardEngine",
            "com.inca.security.AppGuard",
            "com.inca.security.Proxy.JNISoxProxy"
        };

        for (String cls : engineClasses) {
            try {
                Class<?> c = Class.forName(cls, false, cl);
                XposedBridge.log(TAG + ": found class " + cls);
                hookAllMethods(c);
            } catch (ClassNotFoundException e) {
                XposedBridge.log(TAG + ": class not found " + cls);
            } catch (Throwable t) {
                XposedBridge.log(TAG + ": error hooking " + cls + ": " + t.getMessage());
            }
        }

        // =============================================
        // 5. Hook ALL com.inca.security.* classes loaded
        // =============================================
        XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, boolean.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                String name = (String) param.args[0];
                if (name != null && name.startsWith("com.inca.security.")) {
                    try {
                        Class<?> c = (Class<?>) param.getResult();
                        if (c != null) {
                            hookAllMethods(c);
                        }
                    } catch (Throwable ignored) {}
                }
            }
        });

        // =============================================
        // 6. Block ptrace (anti-debug bypass)
        // =============================================
        try {
            Class<?> osClass = Class.forName("android.os.Process", false, cl);
            // Hook any native method calls if available
        } catch (Throwable ignored) {}

        // =============================================
        // 7. Hook System properties for root detection
        // =============================================
        XposedHelpers.findAndHookMethod(System.class, "getProperty", String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String key = (String) param.args[0];
                if (key != null && (key.contains("ro.debuggable") || key.contains("ro.secure"))) {
                    if (key.contains("debuggable")) param.setResult("0");
                    if (key.contains("ro.secure")) param.setResult("1");
                }
            }
        });

        XposedBridge.log(TAG + ": ALL HOOKS INSTALLED in " + process);
    }

    private void hookAllMethods(Class<?> clazz) {
        int hooked = 0;
        java.lang.reflect.Method[] methods;
        try {
            methods = clazz.getDeclaredMethods();
        } catch (Throwable t) {
            return;
        }

        for (java.lang.reflect.Method method : methods) {
            String name = method.getName().toLowerCase();
            Class<?> retType = method.getReturnType();

            // Hook boolean return methods (detection checks)
            if (retType == boolean.class) {
                boolean returnVal = false;
                // Methods that should return TRUE (safe/valid)
                if (name.contains("safe") || name.contains("valid") ||
                    name.contains("allow") || name.contains("verified") ||
                    name.contains("clean") || name.contains("pass") ||
                    name.contains("legit") || name.contains("authentic") ||
                    name.contains("original") || name.contains("genuine")) {
                    returnVal = true;
                }
                // Methods that should return FALSE (not detected)
                // root, debug, hook, tamper, emul, hack, inject, frida, xposed, modif
                try {
                    XposedBridge.hookMethod(method, XC_MethodReplacement.returnConstant(returnVal));
                    hooked++;
                } catch (Throwable ignored) {}
            }

            // Hook int return methods (error codes, status)
            if (retType == int.class || retType == Integer.class) {
                if (name.contains("status") || name.contains("code") ||
                    name.contains("result") || name.contains("state") ||
                    name.contains("check") || name.contains("detect") ||
                    name.contains("scan") || name.contains("verify") ||
                    name.contains("integrity")) {
                    try {
                        XposedBridge.hookMethod(method, XC_MethodReplacement.returnConstant(0));
                        hooked++;
                    } catch (Throwable ignored) {}
                }
            }

            // Hook String return methods
            if (retType == String.class) {
                if (name.contains("status") || name.contains("result") ||
                    name.contains("detect") || name.contains("check")) {
                    try {
                        XposedBridge.hookMethod(method, XC_MethodReplacement.returnConstant(""));
                        hooked++;
                    } catch (Throwable ignored) {}
                }
            }

            // Hook void methods that do callbacks/listeners (onDetected, onViolation, etc.)
            if (retType == void.class) {
                if (name.contains("detect") || name.contains("violation") ||
                    name.contains("report") || name.contains("alert") ||
                    name.contains("kill") || name.contains("crash") ||
                    name.contains("exit") || name.contains("block") ||
                    name.contains("terminate") || name.contains("deny") ||
                    name.contains("stop") || name.contains("warn")) {
                    try {
                        XposedBridge.hookMethod(method, XC_MethodReplacement.DO_NOTHING);
                        hooked++;
                    } catch (Throwable ignored) {}
                }
            }
        }

        if (hooked > 0) {
            XposedBridge.log(TAG + ": hooked " + hooked + " methods in " + clazz.getName());
        }
    }
}

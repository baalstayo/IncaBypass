package com.october.apppealing;

import android.os.Build;
import android.util.Log;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.io.File;
import java.lang.reflect.Method;

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
        // 1. BLOCK ALL FRIDA DETECTION VECTORS
        // =============================================

        // Block Frida-related file checks
        XposedHelpers.findAndHookMethod(File.class, "exists", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String path = ((File) param.thisObject).getAbsolutePath().toLowerCase();
                if (path.contains("/su") || path.contains("magisk") || path.contains("superuser") ||
                    path.contains("frida") || path.contains("xposed") || path.contains("re.frida") ||
                    path.contains("libfrida") || path.contains("frida-server") || path.contains("gadget") ||
                    path.contains("/proc/self/maps") || path.contains("/dev/ashmem") ||
                    path.contains("/data/local/tmp/frida") || path.contains("/system/bin/frida")) {
                    param.setResult(false);
                }
            }
        });

        // Block Frida-related command execution
        XC_MethodHook execHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                Object arg = param.args[0];
                String cmd = (arg instanceof String) ? (String) arg :
                             (arg instanceof String[]) ? String.join(" ", (String[]) arg) : "";
                if (cmd.contains("su") || cmd.contains("magisk") || cmd.contains("which su") ||
                    cmd.contains("frida") || cmd.contains("xposed") || cmd.contains("ps -ef") ||
                    cmd.contains("cat /proc/self/maps") || cmd.contains("grep frida") ||
                    cmd.contains("ls -la /data/local/tmp") || cmd.contains("ls -la /dev/ashmem")) {
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

        // Block Frida-related network checks
        try {
            Class<?> inetAddress = Class.forName("java.net.InetAddress", false, cl);
            XposedHelpers.findAndHookMethod(inetAddress, "getByName", String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String host = (String) param.args[0];
                    if (host.contains("frida") || host.contains("xposed") || host.contains("localhost")) {
                        param.setResult(null);
                    }
                }
            });
        } catch (Throwable ignored) {}

        // =============================================
        // 2. HOOK INCA APPGUARD IN BOTH PROCESSES
        // =============================================

        // Hook INCA AppGuard classes in main process AND service process
        String[] engineClasses = {
            "com.inca.security.Cire.AppGuardEngine",
            "com.inca.security.AppGuard",
            "com.inca.security.Proxy.JNISoxProxy",
            "com.inca.security.Service.AppGuardService"
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
        // 3. HIDE XPOSED FROM INCA DETECTION
        // =============================================

        // Block Xposed detection
        try {
            XposedHelpers.findAndHookMethod("de.robv.android.xposed.XposedBridge", cl, "isXposedLoaded", new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(false);
                }
            });
        } catch (Throwable ignored) {}

        // Block Xposed API checks
        try {
            XposedHelpers.findAndHookMethod("de.robv.android.xposed.XposedHelpers", cl, "findMethodExact",
                String.class, ClassLoader.class, String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    String className = (String) param.args[0];
                    if (className.contains("xposed")) {
                        param.setResult(null);
                    }
                }
            });
        } catch (Throwable ignored) {}

        // =============================================
        // 4. FORCE "SAFE" RESPONSES FOR ALL DETECTION CHECKS
        // =============================================

        // Block all detection methods (root, debug, frida, xposed)
        XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class, boolean.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                String name = (String) param.args[0];
                if (name != null && (name.startsWith("com.inca.security.") || 
                    name.contains("detect") || name.contains("check") || name.contains("verify"))) {
                    try {
                        Class<?> c = (Class<?>) param.getResult();
                        if (c != null) {
                            hookAllMethods(c);
                        }
                    } catch (Throwable ignored) {}
                }
            }
        });

        XposedBridge.log(TAG + ": ALL HOOKS INSTALLED in " + process);
    }

    private void hookAllMethods(Class<?> clazz) {
        int hooked = 0;
        try {
            for (Method method : clazz.getDeclaredMethods()) {
                String name = method.getName().toLowerCase();
                Class<?> retType = method.getReturnType();

                // Hook boolean methods (detection checks)
                if (retType == boolean.class) {
                    boolean returnVal = false;
                    if (name.contains("safe") || name.contains("valid") || name.contains("allow") ||
                        name.contains("pass") || name.contains("clean") || name.contains("legit")) {
                        returnVal = true;
                    }
                    XposedBridge.hookMethod(method, XC_MethodReplacement.returnConstant(returnVal));
                    hooked++;
                }

                // Hook int methods (error codes)
                if (retType == int.class || retType == Integer.class) {
                    if (name.contains("status") || name.contains("code") || name.contains("result")) {
                        XposedBridge.hookMethod(method, XC_MethodReplacement.returnConstant(0));
                        hooked++;
                    }
                }

                // Hook void methods (detection callbacks)
                if (retType == void.class) {
                    if (name.contains("detect") || name.contains("violation") || 
                        name.contains("crash") || name.contains("exit")) {
                        XposedBridge.hookMethod(method, XC_MethodReplacement.DO_NOTHING);
                        hooked++;
                    }
                }
            }
        } catch (Throwable ignored) {}

        if (hooked > 0) {
            XposedBridge.log(TAG + ": hooked " + hooked + " methods in " + clazz.getName());
        }
    }
}

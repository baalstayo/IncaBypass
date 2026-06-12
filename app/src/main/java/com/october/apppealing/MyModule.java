package com.october.apppealing;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
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
import java.util.Iterator;
import java.util.List;

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
        // 1. TOTAL MASK XPOSED (ini kunci!)
        // =============================================

        // Sembunyikan Xposed dari deteksi
        XposedHelpers.findAndHookMethod("de.robv.android.xposed.XposedBridge", cl, "isXposedLoaded", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                param.setResult(false);
            }
        });

        // Sembunyikan Xposed module dari daftar package
        try {
            Class<?> pmClass = Class.forName("android.content.pm.PackageManager", false, cl);
            XposedHelpers.findAndHookMethod(pmClass, "getInstalledPackages", int.class, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) {
                    List<PackageInfo> packages = (List<PackageInfo>) param.getResult();
                    Iterator<PackageInfo> it = packages.iterator();
                    while (it.hasNext()) {
                        PackageInfo pkg = it.next();
                        if (pkg.packageName.equals("de.robv.android.xposed.installer") ||
                            pkg.packageName.equals("com.october.apppealing")) {
                            it.remove();
                        }
                    }
                }
            });
        } catch (Throwable ignored) {}

        // =============================================
        // 2. BLOCK ALL DETECTION VECTORS (lebih komprehensif)
        // =============================================

        // Block file checks
        XposedHelpers.findAndHookMethod(File.class, "exists", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String path = ((File) param.thisObject).getAbsolutePath().toLowerCase();
                if (path.contains("/su") || path.contains("magisk") || path.contains("superuser") ||
                    path.contains("frida") || path.contains("xposed") || path.contains("re.frida") ||
                    path.contains("libfrida") || path.contains("frida-server") || path.contains("gadget") ||
                    path.contains("/proc/self/maps") || path.contains("/dev/ashmem") ||
                    path.contains("/data/local/tmp/frida") || path.contains("/system/bin/frida") ||
                    path.contains("/xposed") || path.contains("/data/app/") ||
                    path.contains("/data/data/") || path.contains("/cache/") ||
                    path.contains("/sdcard/")) {
                    param.setResult(false);
                }
            }
        });

        // Block command execution
        XC_MethodHook execHook = new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                Object arg = param.args[0];
                String cmd = (arg instanceof String) ? (String) arg :
                             (arg instanceof String[]) ? String.join(" ", (String[]) arg) : "";
                if (cmd.contains("su") || cmd.contains("magisk") || cmd.contains("which su") ||
                    cmd.contains("frida") || cmd.contains("xposed") || cmd.contains("ps -ef") ||
                    cmd.contains("cat /proc/self/maps") || cmd.contains("grep frida") ||
                    cmd.contains("ls -la /data/local/tmp") || cmd.contains("ls -la /dev/ashmem") ||
                    cmd.contains("getprop") || cmd.contains("dumpsys") || cmd.contains("adb")) {
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
        // 3. HOOK INCA APPGUARD DI SEMUA PROSES
        // =============================================

        // Hook semua kelas INCA di semua proses
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
        // 4. FORCED "SAFE" RESPONSES
        // =============================================

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

                // Hook boolean methods
                if (retType == boolean.class) {
                    boolean returnVal = false;
                    if (name.contains("safe") || name.contains("valid") || name.contains("allow") ||
                        name.contains("pass") || name.contains("clean") || name.contains("legit")) {
                        returnVal = true;
                    }
                    XposedBridge.hookMethod(method, XC_MethodReplacement.returnConstant(returnVal));
                    hooked++;
                }

                // Hook int methods
                if (retType == int.class || retType == Integer.class) {
                    if (name.contains("status") || name.contains("code") || name.contains("result")) {
                        XposedBridge.hookMethod(method, XC_MethodReplacement.returnConstant(0));
                        hooked++;
                    }
                }

                // Hook void methods
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

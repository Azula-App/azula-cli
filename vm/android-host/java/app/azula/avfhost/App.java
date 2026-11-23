package app.azula.avfhost;

import android.app.Application;
import java.io.File;
import java.lang.reflect.Method;
import org.lsposed.hiddenapibypass.HiddenApiBypass;

public class App extends Application {
    static volatile String bypassResult = "not run";

    @Override public void onCreate() {
        super.onCreate();
        File logs = new File(getFilesDir(), "logs");
        logs.mkdirs();
        Log.dir = logs;
        bypassResult = enableBypass();
        Log.to("host", "hidden-api bypass: " + bypassResult);
    }

    /** A hidden-API-restricted reflective probe: VMRuntime.setHiddenApiExemptions (blocklisted). */
    private static boolean probe() {
        try {
            Method m = Class.forName("dalvik.system.VMRuntime").getDeclaredMethod("setHiddenApiExemptions", String[].class);
            return m != null;
        } catch (Throwable t) {
            return false;
        }
    }

    private static String enableBypass() {
        StringBuilder sb = new StringBuilder();
        boolean before = probe();
        sb.append("probe-before=").append(before);
        try {
            boolean r = HiddenApiBypass.addHiddenApiExemptions("L");
            sb.append(" lsposed-returned=").append(r);
        } catch (Throwable t) {
            sb.append(" lsposed-threw=").append(t);
        }
        boolean after = probe();
        sb.append(" probe-after=").append(after);
        if (!after) {
            // Fallback: meta-reflection to reach VMRuntime.setHiddenApiExemptions.
            try {
                Method forName = Class.class.getDeclaredMethod("forName", String.class);
                Method getDeclaredMethod = Class.class.getDeclaredMethod("getDeclaredMethod", String.class, Class[].class);
                Class<?> vmRuntime = (Class<?>) forName.invoke(null, "dalvik.system.VMRuntime");
                Method getRuntime = (Method) getDeclaredMethod.invoke(vmRuntime, "getRuntime", null);
                Method set = (Method) getDeclaredMethod.invoke(vmRuntime, "setHiddenApiExemptions", new Class[]{String[].class});
                Object rt = getRuntime.invoke(null);
                set.invoke(rt, new Object[]{new String[]{"L"}});
                sb.append(" meta-reflection=ok probe-after-meta=").append(probe());
            } catch (Throwable t) {
                sb.append(" meta-reflection-failed=").append(t);
            }
        }
        // Does the real AVF API resolve and its hidden constructor work?
        try {
            Class<?> c = Class.forName("android.system.virtualmachine.VirtualMachineCustomImageConfig$Builder");
            c.getDeclaredConstructor().newInstance();
            sb.append(" avf-hidden-ctor=ok");
        } catch (Throwable t) {
            sb.append(" avf-hidden-ctor=").append(t);
        }
        return sb.toString();
    }
}

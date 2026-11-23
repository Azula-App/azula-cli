package app.azula.avfhost;

import android.content.Context;
import app.azula.vmhost.AzulaHost;
import java.io.File;
import java.util.Map;

/**
 * Runs the attach-mode broker. With libazula_host.so packaged it runs in this
 * process through {@link AzulaHost}; otherwise (prototype fallback) it execs
 * libazula.so (the azula CLI) as a child and restarts it on exit.
 */
final class Broker {
    private final Context ctx;
    private volatile boolean running;
    private volatile Process proc;
    private Thread thread;

    Broker(Context ctx) { this.ctx = ctx; }

    static boolean jni(Context ctx) { return new File(ctx.getApplicationInfo().nativeLibraryDir, "libazula_host.so").exists(); }

    static String config(Context ctx) {
        File f = ctx.getFilesDir();
        return "{\"computeDir\":\"" + new File(f, "compute").getAbsolutePath()
                + "\",\"vmName\":\"default\",\"workerSocket\":\"" + new File(f, "run/worker.sock").getAbsolutePath()
                + "\",\"vmCpus\":" + Runtime.getRuntime().availableProcessors()
                + ",\"vmMemoryMb\":4096,\"logFile\":\"" + new File(f, "logs/broker.log").getAbsolutePath() + "\"}";
    }

    static File bin(Context ctx) { return new File(ctx.getApplicationInfo().nativeLibraryDir, "libazula.so"); }

    static void env(Context ctx, Map<String, String> e) {
        File f = ctx.getFilesDir();
        e.put("HOME", f.getAbsolutePath());
        e.put("AZULA_COMPUTE_DIR", new File(f, "compute").getAbsolutePath());
        e.put("AZULA_VM_DIR", new File(f, "azvm").getAbsolutePath());
        e.put("RUST_LOG", "info");
    }

    void start() {
        running = true;
        thread = new Thread(this::loop, "broker");
        thread.setDaemon(true);
        thread.start();
    }

    private void loop() {
        File f = ctx.getFilesDir();
        File log = new File(f, "logs/broker.log");
        new File(f, "compute").mkdirs();
        new File(f, "azvm").mkdirs();
        while (running) {
            if (jni(ctx)) {
                String err = AzulaHost.start(config(ctx));
                if (err.isEmpty()) {
                    Log.to("host", "broker: running in-process (libazula_host.so)");
                    return;
                }
                Log.to("host", "broker: start failed: " + err);
                try { Thread.sleep(3000); } catch (InterruptedException e) { return; }
                continue;
            }
            try {
                File bin = bin(ctx);
                String[] cmd = {bin.getAbsolutePath(), "compute", "serve", "--local",
                        "--worker-socket", new File(f, "run/worker.sock").getAbsolutePath(),
                        "--vm-name", "default",
                        "--vm-cpus", String.valueOf(Runtime.getRuntime().availableProcessors()),
                        "--vm-memory-mb", "4096"};
                ProcessBuilder pb = new ProcessBuilder(cmd);
                env(ctx, pb.environment());
                pb.redirectErrorStream(true);
                pb.redirectOutput(ProcessBuilder.Redirect.appendTo(log));
                Log.to("host", "broker: starting " + String.join(" ", cmd));
                proc = pb.start();
                int rc = proc.waitFor();
                Log.to("host", "broker: exited rc=" + rc);
            } catch (InterruptedException e) {
                return;
            } catch (Throwable e) {
                Log.to("host", "broker: failed to run: " + e);
            }
            if (!running) return;
            try { Thread.sleep(3000); } catch (InterruptedException e) { return; }
        }
    }

    void stop() {
        running = false;
        if (jni(ctx)) {
            AzulaHost.stop();
            Log.to("host", "broker: stopped");
            return;
        }
        Process p = proc;
        if (p != null) p.destroy();
        if (thread != null) thread.interrupt();
        Log.to("host", "broker: stopped");
    }
}

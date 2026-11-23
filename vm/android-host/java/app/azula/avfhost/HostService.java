package app.azula.avfhost;

import android.app.Notification;
import app.azula.vmhost.AzulaHost;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.system.Os;
import android.system.virtualmachine.VirtualMachine;
import android.system.virtualmachine.VirtualMachineCallback;
import android.system.virtualmachine.VirtualMachineConfig;
import android.system.virtualmachine.VirtualMachineCustomImageConfig;
import android.system.virtualmachine.VirtualMachineManager;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.concurrent.Executors;

public class HostService extends Service {
    static final String ACTION_START = "app.azula.avfhost.START";
    static final String ACTION_STOP = "app.azula.avfhost.STOP";
    /** Test hook: finish and remove the activity task even while the screen is off. */
    static final String ACTION_CLOSE_UI = "app.azula.avfhost.CLOSE_UI";
    static final String ACTION_MINT = "app.azula.avfhost.MINT";
    static final String ACTION_REVOKE = "app.azula.avfhost.REVOKE";
    static final String VM_NAME = "azula";
    static final String U_BOOT = "/apex/com.android.virt/etc/u-boot.bin";
    static final long DISK_BYTES = 16L << 30;

    static volatile String status = "stopped";

    private volatile VirtualMachine vm;
    private volatile long startedAt;
    private boolean started;
    private PowerManager.WakeLock wakeLock;
    private Bridge bridge;
    private Proxy proxy;
    private Broker broker;

    @Override public IBinder onBind(Intent i) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (action == null) action = ACTION_START;
        Log.to("host", "onStartCommand action=" + action);
        promote();
        switch (action) {
            case ACTION_STOP:
                new Thread(() -> { stopAll(); stopSelf(); }, "stop").start();
                break;
            case ACTION_CLOSE_UI:
                final MainActivity a = MainActivity.current;
                Log.to("host", "CLOSE_UI activity=" + a);
                if (a != null) a.runOnUiThread(a::finishAndRemoveTask);
                break;
            case ACTION_MINT:
                final String ttl = str(intent, "ttl", "6h");
                final String label = str(intent, "label", "avfhost");
                new Thread(() -> mint(ttl, label), "mint").start();
                break;
            case ACTION_REVOKE:
                final String rid = str(intent, "id", "");
                new Thread(() -> revoke(rid), "revoke").start();
                break;
            default:
                new Thread(this::startAll, "start").start();
        }
        return START_NOT_STICKY;
    }

    private static String str(Intent i, String k, String d) {
        String v = i == null ? null : i.getStringExtra(k);
        return v == null || v.isEmpty() ? d : v;
    }

    private void promote() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("host", "AVF host", NotificationManager.IMPORTANCE_LOW));
        Notification n = new Notification.Builder(this, "host")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle("Azula AVF host")
                .setContentText("Linux VM host running")
                .setOngoing(true)
                .build();
        startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
    }

    // ---- start ----

    private synchronized void startAll() {
        if (started) { Log.to("host", "already started"); return; }
        started = true;
        startedAt = System.currentTimeMillis();
        try {
            status = "preparing";
            File files = getFilesDir();
            File vmDir = new File(files, "vm");
            vmDir.mkdirs();
            File disk = stage("disk.raw", vmDir);
            File seed = stage("seed.iso", vmDir);
            if (disk == null) throw new IllegalStateException(
                    "no disk.raw in " + vmDir + " or " + getExternalFilesDir(null));
            // The cloud image is 3 GiB; grow the file (sparse) and let cloud-init's
            // growpart/resizefs expand the root filesystem on boot.
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(disk, "rw")) {
                if (raf.length() < DISK_BYTES) {
                    Log.to("host", "growing disk.raw " + raf.length() + " -> " + DISK_BYTES);
                    raf.setLength(DISK_BYTES);
                }
            }

            PowerManager pm = getSystemService(PowerManager.class);
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "avfhost:vm");
            wakeLock.acquire();

            VirtualMachineCustomImageConfig.Builder ib = new VirtualMachineCustomImageConfig.Builder()
                    .setName(VM_NAME)
                    .setBootloaderPath(U_BOOT)
                    .addDisk(VirtualMachineCustomImageConfig.Disk.RWDisk(disk.getAbsolutePath()));
            if (seed != null) ib.addDisk(VirtualMachineCustomImageConfig.Disk.RODisk(seed.getAbsolutePath()));
            VirtualMachineConfig config = new VirtualMachineConfig.Builder(this)
                    .setCustomImageConfig(ib.build())
                    .setMemoryBytes(4096L * 1024 * 1024)
                    .setCpuTopology(1) // match host
                    .setProtectedVm(false)
                    .setDebugLevel(1) // full
                    .setVmOutputCaptured(true)
                    .build();

            VirtualMachineManager vmm = getSystemService(VirtualMachineManager.class);
            if (vmm == null) throw new IllegalStateException("VirtualMachineManager service unavailable");
            // getOrCreate() returns an existing instance with its OLD config (e.g. without
            // the seed disk), so always start from a fresh instance. Nothing in it is ours to
            // keep: the disk images live in filesDir/vm.
            if (vmm.get(VM_NAME) != null) {
                try { vmm.delete(VM_NAME); } catch (Throwable e) { Log.to("host", "delete failed: " + e); }
            }
            VirtualMachine v = vmm.getOrCreate(VM_NAME, config);
            vm = v;
            v.setCallback(Executors.newSingleThreadExecutor(), callback());
            status = "booting";
            Log.to("host", "VM status before run=" + v.getStatus() + "; calling run()");
            v.run();
            Log.to("host", "run() returned; status=" + v.getStatus() + " (+" + elapsed() + "s)");
            captureConsole(v);

            VsockConnector conn = port -> {
                VirtualMachine cur = vm;
                if (cur == null) throw new IllegalStateException("vm not running");
                return cur.connectVsock(port);
            };
            bridge = new Bridge(new File(files, "run"), conn);
            bridge.start();
            proxy = new Proxy(conn);
            proxy.start();
            broker = new Broker(this);
            broker.start();
        } catch (Throwable e) {
            status = "error: " + e;
            Log.to("host", "start failed: " + android.util.Log.getStackTraceString(e));
            started = false;
        }
    }

    private String elapsed() { return String.format("%.1f", (System.currentTimeMillis() - startedAt) / 1000.0); }

    /** Copy from getExternalFilesDir(null) if missing in filesDir/vm. */
    private File stage(String name, File dir) throws Exception {
        File dst = new File(dir, name);
        if (dst.exists()) return dst;
        File src = new File(getExternalFilesDir(null), name);
        if (!src.exists()) return null;
        status = "copying " + name;
        Log.to("host", "copying " + src + " -> " + dst);
        File tmp = new File(dir, name + ".part");
        Files.copy(src.toPath(), tmp.toPath(), StandardCopyOption.REPLACE_EXISTING);
        if (!tmp.renameTo(dst)) throw new java.io.IOException("rename failed for " + name);
        Log.to("host", "copied " + name + " (" + dst.length() + " bytes)");
        return dst;
    }

    private void captureConsole(final VirtualMachine v) {
        Thread t = new Thread(() -> {
            File logs = new File(getFilesDir(), "logs");
            logs.mkdirs();
            boolean seenLogin = false;
            String tail = "";
            try (InputStream in = v.getConsoleOutput();
                 FileOutputStream out = new FileOutputStream(new File(logs, "console.log"), false)) {
                byte[] buf = new byte[4096];
                int r;
                while ((r = in.read(buf)) >= 0) {
                    out.write(buf, 0, r);
                    out.flush();
                    if (!seenLogin) {
                        tail = (tail + new String(buf, 0, r, java.nio.charset.StandardCharsets.ISO_8859_1));
                        if (tail.length() > 256) tail = tail.substring(tail.length() - 256);
                        if (tail.contains("login:")) {
                            seenLogin = true;
                            status = "running (login prompt)";
                            Log.to("host", "LOGIN prompt seen +" + elapsed() + "s since START");
                        }
                    }
                }
            } catch (Throwable e) {
                Log.to("host", "console reader ended: " + e);
            }
            Log.to("host", "console stream closed");
        }, "console");
        t.setDaemon(true);
        t.start();
    }

    private VirtualMachineCallback callback() {
        return new VirtualMachineCallback() {
            public void onPayloadStarted(VirtualMachine v) { Log.to("host", "cb onPayloadStarted"); }
            public void onPayloadReady(VirtualMachine v) { Log.to("host", "cb onPayloadReady"); }
            public void onPayloadFinished(VirtualMachine v, int code) { Log.to("host", "cb onPayloadFinished " + code); }
            public void onError(VirtualMachine v, int code, String msg) {
                status = "vm error " + code + ": " + msg;
                Log.to("host", "cb onError " + code + " " + msg);
            }
            public void onStopped(VirtualMachine v, int reason) {
                status = "vm stopped (reason " + reason + ")";
                Log.to("host", "cb onStopped reason=" + reason + " (+" + elapsed() + "s)");
            }
            public void onGuestAgentRegistered(VirtualMachine v, int cid) { Log.to("host", "cb onGuestAgentRegistered cid=" + cid); }
        };
    }

    // ---- stop ----

    private synchronized void stopAll() {
        Log.to("host", "stopping");
        if (broker != null) { broker.stop(); broker = null; }
        if (proxy != null) { proxy.stop(); proxy = null; }
        if (bridge != null) { bridge.stop(); bridge = null; }
        VirtualMachine v = vm;
        vm = null;
        if (v != null) {
            try { v.stop(); } catch (Throwable e) { Log.to("host", "vm.stop: " + e); }
            try { v.close(); } catch (Throwable e) { Log.to("host", "vm.close: " + e); }
        }
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        wakeLock = null;
        started = false;
        status = "stopped";
        Log.to("host", "stopped");
    }

    @Override public void onDestroy() {
        stopAll();
        super.onDestroy();
    }

    // ---- token mint ----

    private void mint(String ttl, String label) {
        try {
            File out = new File(getFilesDir(), "token.json");
            if (Broker.jni(this)) {
                String json = AzulaHost.mintGrant(ttl, label);
                try (FileOutputStream f = new FileOutputStream(out)) { f.write(json.getBytes(java.nio.charset.StandardCharsets.UTF_8)); }
                Os.chmod(out.getAbsolutePath(), 0600);
                Log.to("host", "mint (jni) wrote " + json.length() + " bytes to " + out);
                return;
            }
            ProcessBuilder pb = new ProcessBuilder(Broker.bin(this).getAbsolutePath(), "compute", "grant",
                    "--ttl", ttl, "--label", label, "--json");
            Broker.env(this, pb.environment());
            new File(getFilesDir(), "compute").mkdirs();
            pb.redirectError(ProcessBuilder.Redirect.appendTo(new File(getFilesDir(), "logs/broker.log")));
            Process p = pb.start();
            byte[] data = p.getInputStream().readAllBytes();
            int rc = p.waitFor();
            try (FileOutputStream f = new FileOutputStream(out)) { f.write(data); }
            Os.chmod(out.getAbsolutePath(), 0600);
            Log.to("host", "mint rc=" + rc + " wrote " + data.length + " bytes to " + out);
        } catch (Throwable e) {
            Log.to("host", "mint failed: " + e);
        }
    }

    /** Revokes grant {@code id}, or the one in token.json when empty (JNI broker only). */
    private void revoke(String id) {
        try {
            if (id.isEmpty()) {
                File tf = new File(getFilesDir(), "token.json");
                id = new org.json.JSONObject(new String(Files.readAllBytes(tf.toPath()), java.nio.charset.StandardCharsets.UTF_8))
                        .getJSONObject("grant").getString("id");
            }
            boolean ok = AzulaHost.revoke(id);
            Log.to("host", "revoke " + id + " -> " + ok + "; grants: " + AzulaHost.listGrants());
        } catch (Throwable e) {
            Log.to("host", "revoke failed: " + e);
        }
    }
}

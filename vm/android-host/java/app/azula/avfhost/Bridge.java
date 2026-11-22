package app.azula.avfhost;

import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import java.io.File;
import java.util.concurrent.atomic.AtomicInteger;

/** filesDir/run/worker.sock (unix) -> VM vsock port 1024. */
final class Bridge {
    private final File runDir;
    private final VsockConnector vm;
    private volatile boolean running = true;
    private LocalSocket bound;
    private LocalServerSocket server;
    private final AtomicInteger ids = new AtomicInteger();

    Bridge(File runDir, VsockConnector vm) { this.runDir = runDir; this.vm = vm; }

    void start() throws Exception {
        runDir.mkdirs();
        Os.chmod(runDir.getAbsolutePath(), 0700);
        File sock = new File(runDir, "worker.sock");
        sock.delete();
        bound = new LocalSocket(LocalSocket.SOCKET_STREAM);
        bound.bind(new LocalSocketAddress(sock.getAbsolutePath(), LocalSocketAddress.Namespace.FILESYSTEM));
        Os.chmod(sock.getAbsolutePath(), 0600);
        server = new LocalServerSocket(bound.getFileDescriptor());
        Log.to("bridge", "listening on " + sock);
        Thread t = new Thread(this::acceptLoop, "bridge-accept");
        t.setDaemon(true);
        t.start();
    }

    private void acceptLoop() {
        while (running) {
            final LocalSocket c;
            try {
                c = server.accept();
            } catch (Exception e) {
                if (running) Log.to("bridge", "accept failed: " + e);
                return;
            }
            final int id = ids.incrementAndGet();
            Thread t = new Thread(() -> handle(id, c), "bridge-conn-" + id);
            t.setDaemon(true);
            t.start();
        }
    }

    private void handle(int id, LocalSocket c) {
        long t0 = System.currentTimeMillis();
        Log.to("bridge", "#" + id + " accepted");
        ParcelFileDescriptor pfd;
        try {
            pfd = vm.connectVsock(1024);
        } catch (Throwable e) {
            Log.to("bridge", "#" + id + " connectVsock(1024) failed: " + e);
            try { c.close(); } catch (Exception ignored) {}
            return;
        }
        long[] n = Splice.run(new Splice.Local(c), new Splice.Fd(pfd));
        Log.to("bridge", "#" + id + " closed unix->vsock=" + n[0] + "B vsock->unix=" + n[1]
                + "B in " + (System.currentTimeMillis() - t0) + "ms");
    }

    void stop() {
        running = false;
        try { if (server != null) server.close(); } catch (Exception ignored) {}
        try { if (bound != null) bound.close(); } catch (Exception ignored) {}
        new File(runDir, "worker.sock").delete();
        Log.to("bridge", "stopped");
    }
}

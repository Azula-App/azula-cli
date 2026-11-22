package app.azula.avfhost;

import android.os.ParcelFileDescriptor;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Guest-internet proxy. Keeps POOL idle host->guest vsock connections to guest port 3129; the guest
 * sends an HTTP proxy request over one, and we tunnel it to the real network.
 */
final class Proxy {
    static final int POOL = 4;
    static final int PORT = 3129;
    private static final int MAX_HEAD = 16 * 1024;

    private final VsockConnector vm;
    private volatile boolean running = true;
    private final AtomicInteger ids = new AtomicInteger();
    private final Object lock = new Object();
    private final java.util.Set<ParcelFileDescriptor> idle = new java.util.HashSet<>();

    Proxy(VsockConnector vm) { this.vm = vm; }

    void start() {
        for (int i = 0; i < POOL; i++) {
            final int slot = i;
            Thread t = new Thread(() -> slotLoop(slot), "proxy-slot-" + i);
            t.setDaemon(true);
            t.start();
        }
    }

    private void slotLoop(int slot) {
        int failures = 0;
        long lastLogged = 0;
        while (running) {
            ParcelFileDescriptor pfd = null;
            byte[] head = null;
            String why = null;
            try {
                pfd = vm.connectVsock(PORT);
                synchronized (lock) { idle.add(pfd); }
                if (failures > 0) Log.to("proxy", "slot " + slot + " connected after " + failures + " retries");
                failures = 0;
                head = readHead(new java.io.FileInputStream(pfd.getFileDescriptor()));
                if (head == null) why = "closed before request (guest not listening yet?)";
            } catch (Throwable e) {
                String m = String.valueOf(e);
                int nl = m.indexOf('\n');
                why = nl > 0 ? m.substring(0, nl) : m;
            } finally {
                synchronized (lock) { idle.remove(pfd); }
            }
            if (head == null) {
                if (pfd != null) try { pfd.close(); } catch (IOException ignored) {}
                failures++;
                long now = System.currentTimeMillis();
                if (failures == 1 || now - lastLogged > 30_000) {
                    Log.to("proxy", "slot " + slot + " waiting for guest:" + PORT + " (retry " + failures + "): " + why);
                    lastLogged = now;
                }
                if (!running) return;
                try { Thread.sleep(1000); } catch (InterruptedException e) { return; }
                continue;
            }
            // Consumed: hand off to a tunnel thread and immediately replenish this slot.
            final ParcelFileDescriptor p = pfd;
            final byte[] h = head;
            final int id = ids.incrementAndGet();
            Thread t = new Thread(() -> tunnel(id, p, h), "proxy-tunnel-" + id);
            t.setDaemon(true);
            t.start();
        }
    }

    /** Reads until \r\n\r\n (inclusive of any over-read bytes). Null on EOF/oversize. */
    private static byte[] readHead(InputStream in) throws IOException {
        ByteArrayOutputStream acc = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        while (acc.size() < MAX_HEAD) {
            int r = in.read(buf);
            if (r < 0) return null;
            acc.write(buf, 0, r);
            if (indexOfHeadEnd(acc.toByteArray()) >= 0) return acc.toByteArray();
        }
        return null;
    }

    private static int indexOfHeadEnd(byte[] b) {
        for (int i = 0; i + 3 < b.length; i++) {
            if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') return i;
        }
        return -1;
    }

    private void tunnel(int id, ParcelFileDescriptor pfd, byte[] data) {
        Splice.Fd guest = new Splice.Fd(pfd);
        int end = indexOfHeadEnd(data) + 4;
        String line = new String(data, 0, Math.min(data.length, 2048), StandardCharsets.ISO_8859_1);
        line = line.substring(0, Math.max(0, line.indexOf("\r\n")));
        String[] parts = line.split(" ");
        String target = "?";
        Socket s = null;
        try {
            if (parts.length < 2) throw new IOException("malformed request line");
            boolean connect = parts[0].equalsIgnoreCase("CONNECT");
            String host;
            int port;
            if (connect) {
                String hp = parts[1];
                int c = hp.lastIndexOf(':');
                host = c >= 0 ? hp.substring(0, c) : hp;
                port = c >= 0 ? Integer.parseInt(hp.substring(c + 1)) : 443;
                if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
            } else {
                URI u = URI.create(parts[1]);
                if (u.getHost() == null) throw new IOException("not absolute-form: " + parts[1]);
                host = u.getHost();
                if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
                port = u.getPort() >= 0 ? u.getPort() : ("https".equalsIgnoreCase(u.getScheme()) ? 443 : 80);
            }
            target = host + ":" + port;
            s = new Socket();
            s.connect(new InetSocketAddress(host, port), 15_000);
            s.setTcpNoDelay(true);
            if (connect) {
                guest.out().write("HTTP/1.1 200 Connection established\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
                guest.out().flush();
                // Any client bytes that arrived after the CONNECT head go straight to the target.
                if (data.length > end) { s.getOutputStream().write(data, end, data.length - end); s.getOutputStream().flush(); }
            } else {
                s.getOutputStream().write(data);
                s.getOutputStream().flush();
            }
        } catch (Throwable e) {
            Log.to("proxy", "#" + id + " " + (parts.length > 0 ? parts[0] : "?") + " " + target + " connect failed: " + e);
            try {
                guest.out().write("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                        .getBytes(StandardCharsets.ISO_8859_1));
                guest.out().flush();
            } catch (Throwable ignored) {}
            guest.close();
            if (s != null) try { s.close(); } catch (IOException ignored) {}
            return;
        }
        Log.to("proxy", "#" + id + " " + parts[0] + " " + target + " open");
        long[] n = Splice.run(guest, new Splice.Tcp(s));
        Log.to("proxy", "#" + id + " " + target + " closed guest->net=" + n[0] + "B net->guest=" + n[1] + "B");
    }

    void stop() {
        running = false;
        java.util.List<ParcelFileDescriptor> l;
        synchronized (lock) { l = new java.util.ArrayList<>(idle); }
        for (ParcelFileDescriptor p : l) try { p.close(); } catch (IOException ignored) {}
        Log.to("proxy", "stopped");
    }
}

package app.azula.avfhost;

import android.net.LocalSocket;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/** Bidirectional byte pump with half-close propagation. */
final class Splice {
    interface Endpoint {
        InputStream in() throws IOException;
        OutputStream out() throws IOException;
        void shutdownWrite();
        void close();
    }

    static final class Local implements Endpoint {
        final LocalSocket s;
        Local(LocalSocket s) { this.s = s; }
        public InputStream in() throws IOException { return s.getInputStream(); }
        public OutputStream out() throws IOException { return s.getOutputStream(); }
        public void shutdownWrite() { try { s.shutdownOutput(); } catch (Exception ignored) {} }
        public void close() { try { s.close(); } catch (Exception ignored) {} }
    }

    static final class Fd implements Endpoint {
        final ParcelFileDescriptor p;
        private final FileInputStream in;
        private final FileOutputStream out;
        Fd(ParcelFileDescriptor p) {
            this.p = p;
            this.in = new FileInputStream(p.getFileDescriptor());
            this.out = new FileOutputStream(p.getFileDescriptor());
        }
        public InputStream in() { return in; }
        public OutputStream out() { return out; }
        public void shutdownWrite() {
            try { Os.shutdown(p.getFileDescriptor(), OsConstants.SHUT_WR); } catch (Exception ignored) {}
        }
        public void close() { try { p.close(); } catch (Exception ignored) {} }
    }

    static final class Tcp implements Endpoint {
        final Socket s;
        Tcp(Socket s) { this.s = s; }
        public InputStream in() throws IOException { return s.getInputStream(); }
        public OutputStream out() throws IOException { return s.getOutputStream(); }
        public void shutdownWrite() { try { s.shutdownOutput(); } catch (Exception ignored) {} }
        public void close() { try { s.close(); } catch (Exception ignored) {} }
    }

    /** Blocks until both directions finish. Returns {a->b bytes, b->a bytes}. Closes both. */
    static long[] run(final Endpoint a, final Endpoint b) {
        final long[] n = new long[2];
        Thread t = new Thread(() -> n[0] = pump(a, b, null), "splice-a2b");
        t.start();
        n[1] = pump(b, a, null);
        try { t.join(); } catch (InterruptedException ignored) {}
        a.close();
        b.close();
        return n;
    }

    /** Copies src to dst until EOF; propagates half-close; on I/O error tears both ends down. */
    private static long pump(Endpoint src, Endpoint dst, Object unused) {
        long total = 0;
        byte[] buf = new byte[16 * 1024];
        try {
            InputStream in = src.in();
            OutputStream out = dst.out();
            int r;
            while ((r = in.read(buf)) >= 0) {
                if (r == 0) continue;
                out.write(buf, 0, r);
                out.flush();
                total += r;
            }
            dst.shutdownWrite();
        } catch (IOException e) {
            src.close();
            dst.close();
        }
        return total;
    }
}

package app.azula.avfhost;

import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** Appends timestamped lines to filesDir/logs/<name>.log and mirrors them to logcat. */
final class Log {
    static volatile File dir;
    private static final SimpleDateFormat FMT = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);

    static synchronized void to(String name, String msg) {
        android.util.Log.i("avfhost", name + ": " + msg);
        File d = dir;
        if (d == null) return;
        try (FileWriter w = new FileWriter(new File(d, name + ".log"), true)) {
            w.write(FMT.format(new Date()) + " " + msg + "\n");
        } catch (Exception ignored) {
        }
    }
}

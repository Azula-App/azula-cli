package app.azula.vmhost;

/**
 * JNI surface of libazula_host.so (azula-cli's android-host-jni crate): the
 * attach-mode compute broker, run in-process. Names and signatures are fixed
 * by the native exports.
 */
public final class AzulaHost {
    private AzulaHost() {}

    static { System.loadLibrary("azula_host"); }

    /**
     * Starts the broker on a background thread. {@code configJson}:
     * {computeDir, vmName, workerSocket, vmCpus, vmMemoryMb, logFile}.
     * Returns "" once the broker is serving, else an error message.
     */
    public static native String start(String configJson);

    /** Graceful shutdown; returns when the broker has stopped. */
    public static native void stop();

    /** Same JSON as {@code azula compute grant --json}, or {"error": ...}. */
    public static native String mintGrant(String ttl, String label);

    /** JSON array of grants (no secrets), or {"error": ...}. */
    public static native String listGrants();

    /** True if a grant with this id existed. */
    public static native boolean revoke(String id);
}

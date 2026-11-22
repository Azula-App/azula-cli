package android.system.virtualmachine;

/** Compile-only stub. */
public interface VirtualMachineCallback {
    void onPayloadStarted(VirtualMachine vm);
    void onPayloadReady(VirtualMachine vm);
    void onPayloadFinished(VirtualMachine vm, int exitCode);
    void onError(VirtualMachine vm, int errorCode, String message);
    void onStopped(VirtualMachine vm, int reason);
    void onGuestAgentRegistered(VirtualMachine vm, int cid);
}

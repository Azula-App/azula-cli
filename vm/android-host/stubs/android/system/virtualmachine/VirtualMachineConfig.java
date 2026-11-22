package android.system.virtualmachine;

import android.content.Context;

/** Compile-only stub. */
public final class VirtualMachineConfig {
    private VirtualMachineConfig() {}
    public static final class Builder {
        public Builder(Context context) {}
        public Builder setCustomImageConfig(VirtualMachineCustomImageConfig c) { throw new RuntimeException("stub"); }
        public Builder setMemoryBytes(long bytes) { throw new RuntimeException("stub"); }
        public Builder setCpuTopology(int topology) { throw new RuntimeException("stub"); }
        public Builder setProtectedVm(boolean protectedVm) { throw new RuntimeException("stub"); }
        public Builder setDebugLevel(int level) { throw new RuntimeException("stub"); }
        public Builder setVmOutputCaptured(boolean captured) { throw new RuntimeException("stub"); }
        public Builder setVmConsoleInputSupported(boolean supported) { throw new RuntimeException("stub"); }
        public VirtualMachineConfig build() { throw new RuntimeException("stub"); }
    }
}

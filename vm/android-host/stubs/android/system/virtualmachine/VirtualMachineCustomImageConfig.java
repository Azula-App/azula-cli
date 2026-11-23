package android.system.virtualmachine;

/** Compile-only stub. */
public final class VirtualMachineCustomImageConfig {
    private VirtualMachineCustomImageConfig() {}
    public static final class Disk {
        private Disk() {}
        public static Disk RWDisk(String path) { throw new RuntimeException("stub"); }
        public static Disk RODisk(String path) { throw new RuntimeException("stub"); }
    }
    public static final class Builder {
        public Builder() {}
        public Builder setName(String name) { throw new RuntimeException("stub"); }
        public Builder setBootloaderPath(String path) { throw new RuntimeException("stub"); }
        public Builder addDisk(Disk disk) { throw new RuntimeException("stub"); }
        public Builder addParam(String param) { throw new RuntimeException("stub"); }
        public Builder useNetwork(boolean use) { throw new RuntimeException("stub"); }
        public Builder useAutoMemoryBalloon(boolean use) { throw new RuntimeException("stub"); }
        public VirtualMachineCustomImageConfig build() { throw new RuntimeException("stub"); }
    }
}

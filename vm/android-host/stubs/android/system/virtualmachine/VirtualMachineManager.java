package android.system.virtualmachine;

/** Compile-only stub. */
public class VirtualMachineManager {
    private VirtualMachineManager() {}
    public VirtualMachine create(String name, VirtualMachineConfig config) throws VirtualMachineException { throw new RuntimeException("stub"); }
    public VirtualMachine get(String name) throws VirtualMachineException { throw new RuntimeException("stub"); }
    public VirtualMachine getOrCreate(String name, VirtualMachineConfig config) throws VirtualMachineException { throw new RuntimeException("stub"); }
    public void delete(String name) throws VirtualMachineException { throw new RuntimeException("stub"); }
}

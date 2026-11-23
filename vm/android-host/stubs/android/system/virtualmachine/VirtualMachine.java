package android.system.virtualmachine;

import android.os.ParcelFileDescriptor;
import java.io.InputStream;
import java.util.concurrent.Executor;

/** Compile-only stub. */
public class VirtualMachine implements AutoCloseable {
    private VirtualMachine() {}
    public int getStatus() { throw new RuntimeException("stub"); }
    public void setCallback(Executor executor, VirtualMachineCallback callback) { throw new RuntimeException("stub"); }
    public void run() throws VirtualMachineException { throw new RuntimeException("stub"); }
    public void stop() throws VirtualMachineException { throw new RuntimeException("stub"); }
    @Override public void close() { throw new RuntimeException("stub"); }
    public ParcelFileDescriptor connectVsock(long port) throws VirtualMachineException { throw new RuntimeException("stub"); }
    public InputStream getConsoleOutput() throws VirtualMachineException { throw new RuntimeException("stub"); }
    public InputStream getLogOutput() throws VirtualMachineException { throw new RuntimeException("stub"); }
    public VirtualMachineConfig getConfig() { throw new RuntimeException("stub"); }
}

package app.azula.avfhost;

import android.os.ParcelFileDescriptor;

/** Opens host->guest vsock connections (backed by the running VirtualMachine). */
interface VsockConnector {
    ParcelFileDescriptor connectVsock(long port) throws Exception;
}

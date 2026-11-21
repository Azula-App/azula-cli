import Darwin
import Dispatch
import Foundation
import Virtualization

// MARK: - Output helpers (stdout is JSON lines only)

func emit(_ obj: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]),
          var line = String(data: data, encoding: .utf8) else { return }
    line += "\n"
    FileHandle.standardOutput.write(line.data(using: .utf8)!)
}

func log(_ s: String) {
    FileHandle.standardError.write(("azula-vm: " + s + "\n").data(using: .utf8)!)
}

func die(_ msg: String) -> Never {
    log(msg)
    exit(2)
}

// MARK: - Config

struct DiskConfig: Decodable { let path: String; let read_only: Bool? }
struct ShareConfig: Decodable { let tag: String; let path: String; let read_only: Bool? }
struct VsockConfig: Decodable { let socket: String; let port: UInt32 }
struct Config: Decodable {
    let cpus: Int
    let memory_mb: Int
    let machine_id: String
    let mac: String
    let efi_vars: String
    let disks: [DiskConfig]
    let shares: [ShareConfig]?
    /// "nat" (default when absent) or "none" (no network device).
    let network: String?
    let console_log: String
    let vsock: VsockConfig
}

// MARK: - Subcommands: check / init

func cmdCheck() -> Never {
    let v = ProcessInfo.processInfo.operatingSystemVersion
    let ver = "\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    emit([
        "supported": VZVirtualMachine.isSupported,
        "macos": ver,
        "max_cpus": VZVirtualMachineConfiguration.maximumAllowedCPUCount,
        "min_memory_mb": Int(VZVirtualMachineConfiguration.minimumAllowedMemorySize / (1024 * 1024)),
        "max_memory_mb": Int(VZVirtualMachineConfiguration.maximumAllowedMemorySize / (1024 * 1024)),
    ])
    exit(0)
}

func cmdInit(_ args: [String]) -> Never {
    guard let i = args.firstIndex(of: "--efi-vars"), i + 1 < args.count else {
        die("usage: azula-vm init --efi-vars PATH")
    }
    let path = args[i + 1]
    if FileManager.default.fileExists(atPath: path) { die("\(path) already exists") }
    do {
        _ = try VZEFIVariableStore(creatingVariableStoreAt: URL(fileURLWithPath: path))
    } catch {
        die("creating EFI variable store: \(error)")
    }
    emit([
        "machine_id": VZGenericMachineIdentifier().dataRepresentation.base64EncodedString(),
        "mac": VZMACAddress.randomLocallyAdministered().string,
    ])
    exit(0)
}

// MARK: - Byte pumping

func writeAll(_ fd: Int32, _ buf: UnsafeRawPointer, _ n: Int) -> Bool {
    var off = 0
    while off < n {
        let w = write(fd, buf + off, n - off)
        if w < 0 {
            if errno == EINTR { continue }
            return false
        }
        off += w
    }
    return true
}

/// Copy src -> dst until EOF/error, then half-close dst's write side.
func pump(from src: Int32, to dst: Int32) {
    let size = 64 * 1024
    let buf = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 1)
    defer { buf.deallocate() }
    while true {
        let r = read(src, buf, size)
        if r < 0 { if errno == EINTR { continue }; break }
        if r == 0 { break }
        if !writeAll(dst, buf, r) { break }
    }
    shutdown(dst, SHUT_WR)
}

// MARK: - Runner

final class Runner: NSObject, VZVirtualMachineDelegate {
    let config: Config
    let vm: VZVirtualMachine
    var listenFD: Int32 = -1
    var stopRequested = false
    var finished = false
    var starting = true
    var forceTimerArmed = false

    init(config: Config, vm: VZVirtualMachine) {
        self.config = config
        self.vm = vm
        super.init()
        vm.delegate = self
    }

    // All methods below run on the main queue.

    func start() {
        vm.start { [self] result in
            starting = false
            switch result {
            case .success:
                emit(["event": "started"])
                startBridge()
                if stopRequested { stop(grace: 30) }
            case .failure(let err):
                finish(reason: "error", error: "start failed: \(err)")
            }
        }
    }

    func stop(grace: Double) {
        stopRequested = true
        if finished || starting { return }  // applied after start completes
        if vm.state == .running || vm.state == .paused {
            if vm.canRequestStop {
                do { try vm.requestStop() } catch {
                    log("requestStop failed: \(error); forcing")
                    kill()
                    return
                }
            } else {
                kill()
                return
            }
        }
        if !forceTimerArmed {
            forceTimerArmed = true
            DispatchQueue.main.asyncAfter(deadline: .now() + grace) { [self] in
                if !finished { log("grace period elapsed; forcing stop"); kill() }
            }
        }
    }

    func kill() {
        stopRequested = true
        if finished || starting { return }
        vm.stop { [self] err in
            if let err = err { finish(reason: "error", error: "force stop failed: \(err)") }
            else { finish(reason: "requested", error: nil) }
        }
    }

    func finish(reason: String, error: String?) {
        if finished { return }
        finished = true
        if listenFD >= 0 { close(listenFD) }
        unlink(config.vsock.socket)
        var o: [String: Any] = ["event": "stopped", "reason": reason]
        if let e = error { o["error"] = e }
        emit(o)
        exit(reason == "error" ? 1 : 0)
    }

    // VZVirtualMachineDelegate
    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        finish(reason: stopRequested ? "requested" : "guest_shutdown", error: nil)
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        finish(reason: "error", error: "\(error)")
    }

    // MARK: vsock bridge

    func startBridge() {
        let path = config.vsock.socket
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { log("vsock bridge: socket() failed"); return }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        guard path.utf8.count < maxLen else { log("vsock bridge: path too long"); close(fd); return }
        withUnsafeMutablePointer(to: &addr.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: maxLen) { _ = strcpy($0, path) }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, len) }
        }
        guard rc == 0 else { log("vsock bridge: bind failed: \(String(cString: strerror(errno)))"); close(fd); return }
        chmod(path, 0o600)
        guard listen(fd, 16) == 0 else { log("vsock bridge: listen failed"); close(fd); return }
        listenFD = fd
        let port = config.vsock.port
        Thread.detachNewThread { [self] in
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 {
                    if errno == EINTR { continue }
                    return  // listener closed
                }
                DispatchQueue.main.async { self.bridge(c, port: port) }
            }
        }
    }

    func bridge(_ unixFD: Int32, port: UInt32) {
        guard !finished, let dev = vm.socketDevices.first as? VZVirtioSocketDevice else {
            close(unixFD); return
        }
        dev.connect(toPort: port) { result in
            switch result {
            case .failure:
                close(unixFD)
            case .success(let conn):
                // `conn` is captured below, keeping its fd open until both directions finish.
                let vfd = conn.fileDescriptor
                let group = DispatchGroup()
                group.enter()
                Thread.detachNewThread { pump(from: unixFD, to: vfd); group.leave() }
                group.enter()
                Thread.detachNewThread { pump(from: vfd, to: unixFD); group.leave() }
                group.notify(queue: .global()) {
                    close(unixFD)
                    conn.close()
                }
            }
        }
    }
}

// MARK: - run

func buildVM(_ cfg: Config) throws -> VZVirtualMachine {
    let c = VZVirtualMachineConfiguration()
    c.cpuCount = cfg.cpus
    c.memorySize = UInt64(cfg.memory_mb) * 1024 * 1024

    let platform = VZGenericPlatformConfiguration()
    guard let idData = Data(base64Encoded: cfg.machine_id),
          let mid = VZGenericMachineIdentifier(dataRepresentation: idData) else {
        throw NSError(domain: "azula-vm", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid machine_id"])
    }
    platform.machineIdentifier = mid
    c.platform = platform

    let boot = VZEFIBootLoader()
    boot.variableStore = VZEFIVariableStore(url: URL(fileURLWithPath: cfg.efi_vars))
    c.bootLoader = boot

    var storage: [VZStorageDeviceConfiguration] = []
    for d in cfg.disks {
        let att = try VZDiskImageStorageDeviceAttachment(
            url: URL(fileURLWithPath: d.path), readOnly: d.read_only ?? false,
            cachingMode: .automatic, synchronizationMode: .full)
        storage.append(VZVirtioBlockDeviceConfiguration(attachment: att))
    }
    c.storageDevices = storage

    switch cfg.network ?? "nat" {
    case "nat":
        guard let mac = VZMACAddress(string: cfg.mac) else {
            throw NSError(domain: "azula-vm", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid mac"])
        }
        let net = VZVirtioNetworkDeviceConfiguration()
        net.attachment = VZNATNetworkDeviceAttachment()
        net.macAddress = mac
        c.networkDevices = [net]
    case "none":
        c.networkDevices = []
    case let other:
        throw NSError(domain: "azula-vm", code: 1, userInfo: [NSLocalizedDescriptionKey: "invalid network \"\(other)\" (expected \"nat\" or \"none\")"])
    }

    c.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
    c.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]

    let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
    serial.attachment = try VZFileSerialPortAttachment(url: URL(fileURLWithPath: cfg.console_log), append: true)
    c.serialPorts = [serial]

    var fsDevs: [VZDirectorySharingDeviceConfiguration] = []
    for s in cfg.shares ?? [] {
        try VZVirtioFileSystemDeviceConfiguration.validateTag(s.tag)
        let fs = VZVirtioFileSystemDeviceConfiguration(tag: s.tag)
        fs.share = VZSingleDirectoryShare(
            directory: VZSharedDirectory(url: URL(fileURLWithPath: s.path), readOnly: s.read_only ?? true))
        fsDevs.append(fs)
    }
    c.directorySharingDevices = fsDevs

    c.socketDevices = [VZVirtioSocketDeviceConfiguration()]

    try c.validate()
    return VZVirtualMachine(configuration: c, queue: .main)
}

var keepAlive: [DispatchSourceSignal] = []

func cmdRun(_ args: [String]) -> Never {
    guard let i = args.firstIndex(of: "--config"), i + 1 < args.count else {
        die("usage: azula-vm run --config PATH")
    }
    let cfg: Config
    do {
        cfg = try JSONDecoder().decode(Config.self, from: Data(contentsOf: URL(fileURLWithPath: args[i + 1])))
    } catch {
        emit(["event": "stopped", "reason": "error", "error": "reading config: \(error)"])
        exit(1)
    }
    signal(SIGPIPE, SIG_IGN)

    let vm: VZVirtualMachine
    do { vm = try buildVM(cfg) } catch {
        emit(["event": "stopped", "reason": "error", "error": "configuration: \(error)"])
        exit(1)
    }
    let runner = Runner(config: cfg, vm: vm)

    // Signals -> stop(30s)
    for sig in [SIGTERM, SIGINT] {
        signal(sig, SIG_IGN)
        let s = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        s.setEventHandler { runner.stop(grace: 30) }
        s.resume()
        keepAlive.append(s)
    }

    // stdin JSON lines on a background thread
    Thread.detachNewThread {
        while let line = readLine(strippingNewline: true) {
            guard let d = line.data(using: .utf8),
                  let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
                  let op = o["op"] as? String else {
                if !line.trimmingCharacters(in: .whitespaces).isEmpty { log("ignoring bad stdin line: \(line)") }
                continue
            }
            if op == "stop" {
                let g = (o["grace_s"] as? NSNumber)?.doubleValue ?? 30
                DispatchQueue.main.async { runner.stop(grace: g) }
            } else if op == "kill" {
                DispatchQueue.main.async { runner.kill() }
            } else {
                log("unknown op \(op)")
            }
        }
        DispatchQueue.main.async { runner.stop(grace: 30) }  // EOF
    }

    DispatchQueue.main.async { runner.start() }
    dispatchMain()
}

// MARK: - Entry

let argv = CommandLine.arguments
guard argv.count >= 2 else { die("usage: azula-vm check | init --efi-vars PATH | run --config PATH") }
if argv[1] == "check" { cmdCheck() }
else if argv[1] == "init" { cmdInit(Array(argv.dropFirst(2))) }
else if argv[1] == "run" { cmdRun(Array(argv.dropFirst(2))) }
else { die("unknown command \(argv[1])") }

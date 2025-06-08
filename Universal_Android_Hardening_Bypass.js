

Java.perform(function () {
    const File = Java.use('java.io.File');
    const Runtime = Java.use('java.lang.Runtime');
    const Debug = Java.use('android.os.Debug');
    const SystemProperties = Java.use('android.os.SystemProperties');
    const String = Java.use('java.lang.String');
    const SettingsSecure = Java.use('android.provider.Settings$Secure');

    // === 1. Root Checks (File Existence) ===
    console.log("[+] Bypassing file-based root detection...");
    const suspiciousPaths = [
        "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/vendor/bin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su"
    ];
    suspiciousPaths.forEach(path => {
        File.$init.overload('java.lang.String').implementation = function (arg) {
            if (arg === path) {
                console.log("[*] Spoofing file not found:", arg);
                return this.$init.call(this, "/nonexistent");
            }
            return this.$init.call(this, arg);
        };
    });

 	`   // === 2. RootBeer Bypass ===
    console.log("[+] Hooking RootBeer root checks...");
    try {
        const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        const falseOverride = function () { return false; };
        [
            "isRooted", "checkForRoot", "checkForDangerousProps",
            "detectRootManagementApps", "checkForSuBinary",
            "checkForBusyBoxBinary", "checkForRWPaths",
            "checkSuExists", "checkForMagiskBinary", "checkForDangerousBinaries"
        ].forEach(method => {
            if (RootBeer[method]) {
                RootBeer[method].implementation = falseOverride;
            }
        });
    } catch (err) {
        console.log("[-] RootBeer class not found, skipping.");
    }

    // === 3. SSL Pinning Bypass (TrustManager) ===
    console.log("[+] Bypassing SSL Pinning...");
    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    const SSLContext = Java.use('javax.net.ssl.SSLContext');
    const TrustManagerImpl = Java.registerClass({
        name: 'custom.TrustManagerImpl',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function () { },
            checkServerTrusted: function () { },
            getAcceptedIssuers: function () { return []; }
        }
    });
    const TrustManagers = [TrustManagerImpl.$new()];
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
        .implementation = function (km, tm, sr) {
            console.log("[*] Injecting fake TrustManager");
            return this.init(km, TrustManagers, sr);
        };

    // === 4. Developer Options Bypass ===
    SettingsSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int')
        .implementation = function (resolver, name, def) {
            if (name === "development_settings_enabled") {
                console.log("[*] Developer Options check bypassed");
                return 0;
            }
            return this.getInt.call(this, resolver, name, def);
        };

    // === 5. Emulator Check Bypass ===
    const props = {
        "ro.build.fingerprint": "google/Pixel/pixel:12/SPB3.210618.013/1234567:user/release-keys",
        "ro.product.model": "Pixel 5",
        "ro.product.manufacturer": "Google",
        "ro.hardware": "ranchu",
        "ro.kernel.qemu": "0"
    };
    SystemProperties.get.overload('java.lang.String').implementation = function (name) {
        if (props[name]) {
            console.log("[*] Emulator prop spoofed:", name);
            return props[name];
        }
        return this.get.call(this, name);
    };

    // === 6. Frida Detection Bypass ===
    String.contains.implementation = function (search) {
        if (search && search.toLowerCase().includes("frida")) {
            console.log("[*] Frida detection bypassed");
            return false;
        }
        return this.contains(search);
    };

    // === 7. Runtime.exec (su/magisk block) ===
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
        if (cmd.includes("su") || cmd.includes("magisk")) {
            console.log("[*] Blocking Runtime.exec of:", cmd);
            throw new Error("Command blocked");
        }
        return this.exec(cmd);
    };

    // === 8. Flutter Native Hook Example ===
    try {
        const FlutterJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");
        FlutterJNI.nativeInit.implementation = function () {
            console.log("[*] Flutter nativeInit() hooked");
            return this.nativeInit();
        };
    } catch (err) {
        console.log("[-] Flutter class not found, skipping.");
    }
});

// === Native Anti-Debug Bypasses (Global) ===
Interceptor.attach(Module.findExportByName(null, 'read'), {
    onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.count = args[2].toInt32();
    },
    onLeave: function (retval) {
        if (retval > 0) {
            const data = Memory.readUtf8String(this.buf, retval.toInt32());
            if (data.includes("TracerPid:")) {
                const patched = data.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
                Memory.writeUtf8String(this.buf, patched);
                console.log("[*] Patched TracerPid to 0");
            }
        }
    }
});

Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
    onEnter: function (args) {
        console.log("[*] ptrace called, returning 0");
        args[0] = ptr(-1);
    },
    onLeave: function (retval) {
        retval.replace(0);
    }
});

Interceptor.attach(Module.findExportByName(null, 'fork'), {
    onEnter: function () {
        console.log("[*] fork() called, bypassing");
    },
    onLeave: function (retval) {
        retval.replace(1234); // fake child pid
    }
});

Interceptor.attach(Module.findExportByName(null, 'open'), {
    onEnter: function (args) {
        const path = Memory.readUtf8String(args[0]);
        if (path.includes("su") || path.includes("magisk") || path.includes("Superuser")) {
            console.log("[*] open() to root file blocked:", path);
            args[0] = Memory.allocUtf8String("/nonexistent");
        }
    }
});

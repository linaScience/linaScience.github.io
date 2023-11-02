+++
title = 'OBTS training'
date = 2023-10-04T13:50:06+02:00
+++

Since I am one of the nine scholars at OBTS v6.0 I want to write about my experience at the training and conference on this blog.

The OBTS is a five-day long event, consisting of three days of training followed by two days of conference.
I am taking part in the "Practical iOS App, User-, and Kernel-Space Reverse-Engineering" training by Jiska Classen and Fabian Freyer.

## Day 1

We started the day with taking a look into the basics of reverse engineering of iOS devices. In particular, we looked at the [Apple Developer API](https://developer.apple.com/documentation/technologies) and talked about which framework could be used to implement a VPN on iOS (hint: it's the [Network Extension](https://developer.apple.com/documentation/networkextension)).

After this we were setting up our lab. Fortunately, I got a jailbroken iPhone 8 with iOS 16.4.1 from the instructors since I hadn't a spare one to jailbreak.
For the tooling to reverse an iOS Application I use my ARM Mac with the following tools:

* `ghidra` (`brew install --cask --no-quarantine ghidra`)
* `swift` (part of Xcode)
* `vscode` with `frida` extension
* `frida` (`pip install frida-tools`)
* `xpcspy` (`pip install --no-deps xpcspy`)
* `lief` (`pip install lief`)
* `libusbmuxd` (`brew install libusbmuxd`)
* `libimobiledevice` (`brew install libimobiledevice`)
* `libplist` (`brew install libplist`)
* `ldid` (`brew install ldid`)
* `pyimg4` (`pip install pyimg4`)
* `DydlExtractor` (`pip install dyldextractor`)
* `frida-devkit-core` (for me, it was [this](https://github.com/frida/frida/releases/download/16.1.4/frida-core-devkit-16.1.4-macos-arm64.tar.xz`))
* [fpicker](https://github.com/ttdennis/fpicker#requirements-and-installation)

### Application Permissions and Review

We also talked about iOS Application Permissions and the difference between entitlements and protected resources.
Entitlements are a right or privilege that grants particular capabilities to an executable of an application. They are listed in the `.plist` files.
Protected resources are requested upon first use or when needed, like the camera or microphone for Instagram or WhatsApp. The applications ask for your consent.
But, guess what, entitlements do exist and do not ask for your permission, so they may run in background without you knowing it.

Widely known, Apple is reviewing applications before they are published in the App Store and there are several reasons why an application may be rejected. So some Enterprises have custom applications and don't want to publish their application for a good reason. This is why you can officially bypass this review process by downloading apps from any URL, via AirDrop, etc.
This is also seen in the wild with for malware distribution, which Google Project Zero has [written about](https://googleprojectzero.blogspot.com/2022/06/curious-case-carrier-app.html).

### Ghidra analysis of an iOS Application

We proceeded with a static analysis with `ghidra` of an iOS Application called `WeiaGuard`.
A log function called `write_msg_to_file` was found and rose our interest. It's writing a message to a file called `WeiaGuard-<yyyy-mm-hh-ssssss>.ips`.

### Dynamic analysis with Frida

Last but not least for the day was a dynamic analysis. I only knew `gdb` as a tool to dynamically analyze executables when playing CTFs but `frida` is a great tool to do this on iOS.
We got introduced into the features of `frida` like it is aware of Objective-C internals, that there is a JavaScript API to interact with the application and that there are hooks, like in "normal" JavaScript.
We used `frida-trace -U WeiaGuard -i 'write_msg_to_log'` to print the parameters of the logging function with this JavaScript code:

```javascript
const wg_log_addr = Module.findExportByName("WeiaGuard", "write_msg_to_log");
const wg_log = new NativeFunction(
    wg_log_addr,
    "void", ["pointer", "pointer", "pointer"], {
});

var wg_log_global_ptr = null;

Interceptor.attach(wg_log_addr, {
    onEnter: function(args) {
        wg_log_global_ptr = new NativePointer(args[0]);
        console.log(`logging the following message: ${args[2].readCString()}`);
    },
});
```

## Day 2

We started where we left the day before and continued with the dynamic analysis of the `WeiaGuard` application and broaden our knowledge about `frida` and its scripting capabilities.

### Fuzzing

Today's goal is to be able to fuzz the application, which is basically automating to find bugs with input which may not be intended by the developer. Fuzzers often try to start with some input and then mutate it, like flipping a bit or swap some bytes, insert or delete something. This amount of mutations is called corpus. You want a big and diverse corpus when fuzzing, because you want to find as many bugs as possible.
We learned of `frida stalker` which collects the coverage of the function execution.
Followed by a very powerful tool called [fpicker](https://github.com/ttdennis/fpicker) which is an advanced fuzzing suite for `frida`.
With this fuzzing suite we were able to generate crash logs which we then tried to analyze.
Unfortunately, for iOS 16 they changed the crash log format and we were not able to analyze the crash logs with the macs console or xcode.

### GCD

GCD stands for Grand Central Dispatch, and it's Apple's implementation of threads. It's a thread pool with a queue. You can add tasks to the queue and the GCD will execute them.
We tried to follow along the threads and wrote a hook for the `dispatch_async` function:

```javascript
// Get queue label
var _dispatch_queue_get_label_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_queue_get_label');
var _dispatch_queue_get_label = new NativeFunction(this._dispatch_queue_get_label_addr, "pointer", ["pointer"]);
function get_queue_label(dispatch_queue) {
   return _dispatch_queue_get_label(dispatch_queue).readUtf8String();
}

// print backtrace
function get_backtrace(ctx) {
       return Thread.backtrace(ctx, Backtracer.ACCURATE)
       .map(DebugSymbol.fromAddress).join('\n');
}

// hook dispatch_async
var _dispatch_async_addr = Module.getExportByName('libdispatch.dylib', 'dispatch_async');
Interceptor.attach(_dispatch_async_addr, {
   onEnter: function(args) {
       console.log('\n------\ndispatch_async \n'
       + 'queue: ' + get_queue_label(args[0]) + '\n'
       + 'backtrace: \n' + get_backtrace(this.context));
   },
});
```

Now, every time we click a button in the application, we get a backtrace of the thread which executed the function.

We ended with a static analysis of this in ghidra.

## Day 3

Today we've done a lot of low level stuff.

### XPC and Mach Ports

First we dived into XPC which is Cross Process Communication in iOS and macOS.
Processes like apps, daemons etc. can exchange messages through XPC.
It's the default communication path, although another may exist.
Permissions are managed by `launchd`, which starts the processes if needed and bootstraps the underlying Mach ports for XPC.
Each Mach port has one send and one receive right. Each process can create a port and hand over the send right to another process. The receiving process can then receive messages from the port.

We used `xpcspy` to take a look into the XPC traffic of the `WeiaGuard` application and listed the Mach ports with the `lsmp` command. We needed to find out the process ID of the `WeiaGuard` application, and then we could list the ports with `lsmp -p <pid>`.

Mach ports and messages are very powerful primitives to build an RPC mechanism into the kernel, because the Mach ports are handles to kernel objects.

### Kernel

The next step would be to get into the kernel, because Mach ports and messages are very powerful primitives to build an RPC mechanism into the kernel, because Mach ports are handles to kernel objects.
In general, there is MIG, the Mach Interface Generator, which is a tool to generate the RPC code for the kernel.

We than looked into some BSD syscalls and Mach messages in the XNU Source code in groups of three and discussed them in the big group.

After that, we unpacked the kernelcache of a restored iPhone with `pyimg4` and extracted the full kernel cache with `kextex`.

## IOKit

IOKit is a driver framework for iOS and macOS. It's a C++ framework and is used to communicate with the kernel based on Mach messages.
The user-spaced and kernel-spaced part of IOKit is open-source and documented. Unfortunately, the drivers are not open-source and not documented.
Therefore, we looked into a driver of the `WeiaGuard` application, and loaded the kext `com.apple.driver.AppleJPEGDriver`, which is used by the app, into ghidra.

## Co-processors

We also talked a bit about different co-processors on iPhones, and there are many, like the cellular baseband chips from intel or wireless combo chips from Broadcom for Wi-Fi and Bluetooth.
But since the new iPhones Apple also started to produce their own wireless co-processors.

And that's the training.
I was able to learn a lot and I am looking forward to the conference days.

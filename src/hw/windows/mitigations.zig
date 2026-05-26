const std = @import("std");
const builtin = @import("builtin");

comptime {
    if (builtin.os.tag != .windows) @compileError("mitigations is Windows-specific");
}

const windows = std.os.windows;

const ProcessDEPPolicy = extern struct {
    Enable: windows.BOOL,
    Permanent: windows.BOOL,
};

const ProcessASLRPolicy = extern struct {
    EnableForceRelocateImages: windows.BOOL,
    RequireRelocateImages: windows.BOOL,
    EnableBottomUpRandomization: windows.BOOL,
    EnableHighEntropy: windows.BOOL,
    DisallowStrippedImages: windows.BOOL,
};

const ProcessStrictHandleCheckPolicy = extern struct {
    HandleExceptionsPermanently: windows.BOOL,
    RaiseExceptionOnInvalidHandle: windows.BOOL,
};

const ProcessSystemCallDisablePolicy = extern struct {
    DisallowWin32kSystemCalls: windows.BOOL,
};

const ProcessExtensionPointDisablePolicy = extern struct {
    DisableExtensionPoints: windows.BOOL,
};

const ProcessSignaturePolicy = extern struct {
    MicrosoftSignedOnly: windows.BOOL,
};

const ProcessImageLoadPolicy = extern struct {
    NoRemoteImages: windows.BOOL,
    NoLowMandatoryLabelImages: windows.BOOL,
    PreferSystem32Images: windows.BOOL,
};

const ProcessMitigationPolicy = u32;

const ProcessDEPPolicyId: ProcessMitigationPolicy = 0;
const ProcessASLRPolicyId: ProcessMitigationPolicy = 1;
const ProcessStrictHandleCheckPolicyId: ProcessMitigationPolicy = 2;
const ProcessSystemCallDisablePolicyId: ProcessMitigationPolicy = 3;
const ProcessExtensionPointDisablePolicyId: ProcessMitigationPolicy = 4;
const ProcessSignaturePolicyId: ProcessMitigationPolicy = 8;
const ProcessImageLoadPolicyId: ProcessMitigationPolicy = 9;

extern "kernel32" fn SetProcessMitigationPolicy(
    policy: ProcessMitigationPolicy,
    lpBuffer: *const anyopaque,
    dwLength: windows.SIZE_T,
) callconv(windows.WINAPI) windows.BOOL;

pub const MitigationFlags = struct {
    dep: bool = true,
    aslr: bool = true,
    high_entropy_aslr: bool = true,
    strict_handles: bool = true,
    no_win32k: bool = true,
    no_extension_points: bool = true,
    block_non_microsoft: bool = false,
    no_remote_images: bool = true,
    no_low_label_images: bool = true,
};

fn applyPolicy(policy_type: ProcessMitigationPolicy, buffer: *const anyopaque, size: windows.SIZE_T) !void {
    const ok = SetProcessMitigationPolicy(policy_type, buffer, size);
    if (ok == 0) return error.MitigationPolicyFailed;
}

pub fn apply(flags: MitigationFlags) !void {
    if (builtin.os.tag != .windows) return error.UnsupportedPlatform;

    if (flags.dep) {
        const policy = ProcessDEPPolicy{
            .Enable = windows.TRUE,
            .Permanent = windows.TRUE,
        };
        try applyPolicy(ProcessDEPPolicyId, &policy, @sizeOf(@TypeOf(policy)));
    }
    if (flags.aslr) {
        const policy = ProcessASLRPolicy{
            .EnableForceRelocateImages = windows.TRUE,
            .RequireRelocateImages = windows.FALSE,
            .EnableBottomUpRandomization = windows.TRUE,
            .EnableHighEntropy = if (flags.high_entropy_aslr) windows.TRUE else windows.FALSE,
            .DisallowStrippedImages = windows.FALSE,
        };
        try applyPolicy(ProcessASLRPolicyId, &policy, @sizeOf(@TypeOf(policy)));
    }
    if (flags.strict_handles) {
        const policy = ProcessStrictHandleCheckPolicy{
            .HandleExceptionsPermanently = windows.TRUE,
            .RaiseExceptionOnInvalidHandle = windows.TRUE,
        };
        try applyPolicy(ProcessStrictHandleCheckPolicyId, &policy, @sizeOf(@TypeOf(policy)));
    }
    if (flags.no_win32k) {
        const policy = ProcessSystemCallDisablePolicy{
            .DisallowWin32kSystemCalls = windows.TRUE,
        };
        try applyPolicy(ProcessSystemCallDisablePolicyId, &policy, @sizeOf(@TypeOf(policy)));
    }
    if (flags.no_extension_points) {
        const policy = ProcessExtensionPointDisablePolicy{
            .DisableExtensionPoints = windows.TRUE,
        };
        try applyPolicy(ProcessExtensionPointDisablePolicyId, &policy, @sizeOf(@TypeOf(policy)));
    }
    if (flags.block_non_microsoft) {
        const policy = ProcessSignaturePolicy{
            .MicrosoftSignedOnly = windows.TRUE,
        };
        try applyPolicy(ProcessSignaturePolicyId, &policy, @sizeOf(@TypeOf(policy)));
    }
    if (flags.no_remote_images or flags.no_low_label_images) {
        const policy = ProcessImageLoadPolicy{
            .NoRemoteImages = if (flags.no_remote_images) windows.TRUE else windows.FALSE,
            .NoLowMandatoryLabelImages = if (flags.no_low_label_images) windows.TRUE else windows.FALSE,
            .PreferSystem32Images = windows.FALSE,
        };
        try applyPolicy(ProcessImageLoadPolicyId, &policy, @sizeOf(@TypeOf(policy)));
    }
}

pub fn applyLowIntegrity() !void {
    if (builtin.os.tag != .windows) return error.UnsupportedPlatform;

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_WRITE: u32 = 0x0020;
    const TokenIntegrityLevel: u32 = 0x19;

    var token: windows.HANDLE = undefined;
    if (windows.OpenProcessToken(windows.GetCurrentProcess(), TOKEN_QUERY | TOKEN_WRITE, &token) == 0) return error.TokenOpenFailed;
    defer _ = windows.CloseHandle(token);

    const TOKEN_MANDATORY_LABEL = extern struct {
        Label: windows.SID_AND_ATTRIBUTES,
    };

    var tml = TOKEN_MANDATORY_LABEL{
        .Label = .{
            .Sid = undefined,
            .Attributes = 0x00000020,
        },
    };

    _ = windows.SetTokenInformation(token, TokenIntegrityLevel, &tml, @sizeOf(@TypeOf(tml)));
}

test "mitigation flags have defaults" {
    const flags = MitigationFlags{};
    try std.testing.expect(flags.dep);
    try std.testing.expect(flags.no_win32k);
}

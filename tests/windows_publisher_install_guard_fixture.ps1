# SPDX-FileCopyrightText: 2026 Jules C
# SPDX-License-Identifier: MIT
# Private hosted fixture: native installation mutex only; no product writes.
if(-not ('UskPublisherInstallGuardEvents' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public sealed class UskPublisherInstallGuardEvents : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct Attributes { public int size; public IntPtr descriptor; public int inherit; }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateEvent(ref Attributes attributes, bool manual, bool initial, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetEvent(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr LocalFree(IntPtr pointer);
    IntPtr ready, release, descriptor;
    public readonly string ReadyName, ReleaseName;
    public UskPublisherInstallGuardEvents() {
        string prefix="Global\\USK_INSTALL_GUARD_"+Guid.NewGuid().ToString("N");
        ReadyName=prefix+"_ready"; ReleaseName=prefix+"_release";
    }
    public void CreateOwned() {
        if(ready!=IntPtr.Zero || release!=IntPtr.Zero || descriptor!=IntPtr.Zero) throw new InvalidOperationException("owned events already initialized");
        uint size;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptor("O:SYG:SYD:P(A;;GA;;;SY)",1,out descriptor,out size)) throw new Win32Exception();
        var attributes=new Attributes {size=Marshal.SizeOf(typeof(Attributes)),descriptor=descriptor,inherit=0};
        ready=CreateEvent(ref attributes,true,false,ReadyName);
        int error=Marshal.GetLastWin32Error();
        if(ready==IntPtr.Zero || error==183) throw new InvalidOperationException("owned ready event creation differs: "+error);
        release=CreateEvent(ref attributes,true,false,ReleaseName);
        error=Marshal.GetLastWin32Error();
        if(release==IntPtr.Zero || error==183) throw new InvalidOperationException("owned release event creation differs: "+error);
    }
    public bool WaitReady(uint milliseconds) {
        uint result=WaitForSingleObject(ready,milliseconds);
        if(result==0) return true;
        if(result==258) return false;
        throw new Win32Exception();
    }
    public void Release() { if(!SetEvent(release)) throw new Win32Exception(); }
    // Inert delegates also exercise the exact close/retention path offline.
    public static void CloseTracked(ref IntPtr value, Func<IntPtr,bool> close, Func<int> error) {
        if(value==IntPtr.Zero) return;
        if(!close(value)) throw new Win32Exception(error());
        value=IntPtr.Zero;
    }
    public static void RunAllCleanup(Action[] actions) {
        Exception first=null;
        foreach(Action action in actions) {
            try {action();} catch(Exception error) {if(first==null) first=error;}
        }
        if(first!=null) throw first;
    }
    public void Dispose() {
        RunAllCleanup(new Action[] {
            ()=>CloseTracked(ref ready, CloseHandle, Marshal.GetLastWin32Error),
            ()=>CloseTracked(ref release, CloseHandle, Marshal.GetLastWin32Error),
            ()=>CloseTracked(ref descriptor, value=>LocalFree(value)==IntPtr.Zero, Marshal.GetLastWin32Error)
        });
    }
}
'@
}
function Read-InstallGuardFixtureOutput([string]$Path) {
    # Start-Process keeps its redirect writer open while the child holds the
    # mutex. A reader must allow that existing writer, while bounding and
    # rechecking the exact bytes that form the readiness observation.
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
    try {
        $length=$stream.Length
        if($length -gt 4KB){throw 'Installation holder output exceeds bound'}
        $bytes=[byte[]]::new([int]$length);$offset=0
        while($offset -lt $bytes.Length) {
            $count=$stream.Read($bytes,$offset,$bytes.Length-$offset)
            if($count -le 0){throw 'Installation holder output ended during observation'}
            $offset+=$count
        }
        if($stream.Length -ne $length -or $stream.ReadByte() -ne -1){throw 'Installation holder output changed during observation'}
        $digest=[Security.Cryptography.SHA256]::Create()
        try {$sha=([BitConverter]::ToString($digest.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}
        finally {$digest.Dispose()}
        return [pscustomobject]@{text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes);sha256=$sha;bytes=$length}
    } finally {$stream.Dispose()}
}
function Read-InstallGuardFixtureReadyOutput([string]$Path,$Holder,[ValidateRange(1,10000)][int]$TimeoutMilliseconds=10000) {
    # The native event follows its stdout flush, but Start-Process forwards
    # the redirected line asynchronously. Incomplete output cannot establish
    # readiness; retain the live child's custody throughout this bounded wait.
    $watch=[Diagnostics.Stopwatch]::StartNew()
    do {
        if($Holder.HasExited){throw 'Installation holder exited before readiness output'}
        $output=Read-InstallGuardFixtureOutput $Path
        if($output.bytes -gt 0 -and $output.text.EndsWith("`n")) {
            if($Holder.HasExited){throw 'Installation holder exited during readiness output'}
            return $output
        }
        [Threading.Thread]::Sleep(10)
    } while($watch.ElapsedMilliseconds -lt $TimeoutMilliseconds)
    throw 'Installation holder complete readiness output is unconfirmed'
}
function Complete-InstallGuardFixtureCleanup($Holder,$Events,$HeldImage,[bool]$LaunchAttempted,[bool]$NormalExit) {
    $closed=$true;$first=$null
    $processClosed=$NormalExit
    $script:installGuardRetainedProcess=$Holder
    $script:installGuardRetainedEvents=$Events
    $script:installGuardRetainedImage=$HeldImage
    if($Holder -and -not $NormalExit) {
        if($Events) {try {$Events.Release()}catch {$closed=$false;$first=$_}}
        try {
            # This private native child launches no descendants. Give its
            # release path time to close normally before failure-only tree
            # cancellation observes a disappearing process through CIM.
            if(-not $Holder.WaitForExit(10000)) {
                $closure=Stop-OwnedPublisherProcessTree $Holder
                if($closure.confirmed -ne $true){throw 'Installation holder process closure is unconfirmed'}
            } else {
                $Holder.WaitForExit()
                if(-not $Holder.HasExited){throw 'Installation holder normal closure is unconfirmed'}
            }
            $processClosed=$true
        } catch {$closed=$false;if(-not $first){$first=$_}}
    } elseif($LaunchAttempted -and -not $Holder) {
        $closed=$false;$first=[InvalidOperationException]::new('Installation holder launch custody is unconfirmed')
    }
    # Attempt every disposal. A failed resource keeps its actual reference;
    # closure is never promoted merely because the child already exited.
    foreach($resource in @(
        @{name='installGuardRetainedProcess';value=$Holder},
        @{name='installGuardRetainedEvents';value=$Events},
        @{name='installGuardRetainedImage';value=$HeldImage})) {
        if($resource.value) {
            if($resource.name -ceq 'installGuardRetainedProcess' -and -not $processClosed){continue}
            try {$resource.value.Dispose();Set-Variable -Scope Script -Name $resource.name -Value $null}
            catch {$closed=$false;if(-not $first){$first=$_}}
        }
    }
    return [pscustomobject]@{confirmed=$closed;first_error=$first}
}
function Invoke-InstallGuardVerificationConflict($Verify) {
    if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne 'S-1-5-18' -or
        $receipt.source_free -ne $true -or $receipt.readbacks.Count -ne 3 -or
        (Get-Service $service).Status -ne 'Stopped') {throw 'Installation guard fixture context differs'}
    # Recheck the actual owned non-system VHD, rather than trusting fixture JSON.
    $ownedImage=Get-DiskImage -ImagePath $VhdPath -ErrorAction Stop
    $ownedDisk=$ownedImage|Get-Disk -ErrorAction Stop
    $ownedParts=@($ownedDisk|Get-Partition|Where-Object DriveLetter)
    if(-not $ownedImage.Attached -or $ownedDisk.IsBoot -or $ownedDisk.IsSystem -or
        $ownedDisk.Number -ne $disk.Number -or $ownedParts.Count -ne 1 -or
        ($ownedParts[0]|Get-Volume).UniqueId -cne $VolumeRoot) {throw 'Installation guard owned target differs'}
    $buildDirectory=Split-Path -Parent ([IO.Path]::GetFullPath($MachineBinary))
    $binary=Join-Path $buildDirectory 'usk_publisher_install_guard_holder.exe'
    $project=Join-Path $publisherBuild 'usk_publisher_install_guard_holder.vcxproj'
    if(-not [IO.File]::Exists($binary) -or -not [IO.File]::Exists($project) -or
        (Get-Item -LiteralPath $binary).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'Current private guard holder is unavailable'
    }
    $events=$null;$holder=$null;$heldImage=$null;$launchAttempted=$false;$normalExit=$false;$guardFailure=$null
    $stdout=Join-Path $lab ('install-guard-'+[guid]::NewGuid().ToString('N')+'.stdout')
    $stderr=$stdout+'.stderr'
    $script:installGuardHolderClosed=$false
    try {
        $heldImage=[IO.File]::Open($binary,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $imageSha=(Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        $events=[UskPublisherInstallGuardEvents]::new()
        $events.CreateOwned()
        $launchAttempted=$true
        $holder=Start-Process -FilePath $binary -ArgumentList @($VolumeRoot,$installed.install_id,$events.ReadyName,$events.ReleaseName,$sid) `
            -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $null=$holder.Handle
        $birth=$holder.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        if($holder.Path -cne $binary -or $holder.HasExited -or -not $events.WaitReady(10000) -or $holder.HasExited) {
            throw 'Held installation guard did not become ready'
        }
        if((Get-Item -LiteralPath $stdout).Length -gt 4KB -or (Get-Item -LiteralPath $stderr).Length -ne 0) {
            throw 'Native installation guard readiness budget differs'
        }
        $readyOutput=Read-InstallGuardFixtureReadyOutput $stdout $holder
        $nativeReadyText=$readyOutput.text
        $nativeReady=$nativeReadyText|ConvertFrom-Json
        if($nativeReady.schema -cne 'usk.publisher_install_guard_holder.v1' -or
            $nativeReady.scope -cne 'owned_installation_mutex_only_no_product_effects' -or
            $nativeReady.process_id -ne $holder.Id -or $nativeReady.creation_file_time -cne $birth -or
            $nativeReady.identity -cne 'S-1-5-18' -or $nativeReady.install_id -cne $installed.install_id -or
            $nativeReady.service_sid -cne $sid -or
            $nativeReady.coordination_acl_scope -cne 'system_and_registered_service_sid_only' -or
            $null -eq $nativeReady.coordination_security -or
            $nativeReady.publication_authority_granted -ne $false -or
            $nativeReady.operation_inspection_ref -cnotmatch '^usk\.operation-inspection\.v1:[0-9a-f]{64}$') {
            throw 'Actual native installation holder binding differs'
        }
        $receipt['installation_guard_conflict']=[ordered]@{
            schema='usk.publisher_install_guard_conflict.v1';
            scope='actual_native_installation_mutex_authenticated_source_free_verify';
            profile_qualified=$false;publication_authority_granted=$false;source_free=$true;
            verify_payload=$Verify;before_readback_index=2;after_release_readback_index=3;
            holder=[ordered]@{native_ready=$nativeReady;native_ready_json=$nativeReadyText;image_path=$binary;image_sha256=$imageSha;
                project_sha256=(Get-FileHash -LiteralPath $project -Algorithm SHA256).Hash.ToLowerInvariant();
                ready_sha256=$readyOutput.sha256;
                parent_process_id=$PID;parent_creation_file_time=$ownerCreation;volume_root=$VolumeRoot;
                events_scope='unique_protected_system_only_ready_and_release';
                alive_before_request=$true;alive_after_response=$false;alive_after_readback=$false;
                normal_release_confirmed=$false;exit_code=$null};
            client_capture=$null;response=$null;exit_code=$null;native_observation=$null;after_refusal_readback=$null}
        $null=Invoke-StandardRequest 'installed.verify' $Verify 4 -InstallGuardRefusal
        if($holder.HasExited){throw 'Installation holder exited before the authenticated response'}
        $receipt.installation_guard_conflict.holder.alive_after_response=$true
        $readback=Read-InstalledSnapshot
        $before=$receipt.readbacks[2]
        if(($readback.independent.rows|ConvertTo-Json -Depth 64 -Compress) -cne
                ($before.independent.rows|ConvertTo-Json -Depth 64 -Compress) -or
            ($readback.independent.volume_boundary|ConvertTo-Json -Depth 64 -Compress) -cne
                ($before.independent.volume_boundary|ConvertTo-Json -Depth 64 -Compress)) {
            throw 'Installation mutex refusal changed protected target or boundary'
        }
        $receipt.installation_guard_conflict.after_refusal_readback=$readback
        if($holder.HasExited){throw 'Installation holder exited before independent refusal readback'}
        $receipt.installation_guard_conflict.holder.alive_after_readback=$true
        $events.Release()
        if(-not $holder.WaitForExit(10000)){throw 'Owned installation holder normal exit is unconfirmed'}
        $holder.WaitForExit()
        if($holder.ExitCode -ne 0 -or (Get-Item -LiteralPath $stderr).Length -ne 0 -or
            (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $imageSha -or
            (Get-FileHash -LiteralPath $stdout -Algorithm SHA256).Hash.ToLowerInvariant() -cne
                $receipt.installation_guard_conflict.holder.ready_sha256) {throw 'Installation holder completion differs'}
        $receipt.installation_guard_conflict.holder.exit_code=$holder.ExitCode
        $receipt.installation_guard_conflict.holder.normal_release_confirmed=$true
        $normalExit=$true
    } catch {
        $guardFailure=$_
        $diagnostic=[ordered]@{stdout=$null;stderr=$null;exit_code=$null;diagnostic_failure=$null}
        try {
            foreach($entry in @(@{role='stdout';path=$stdout},@{role='stderr';path=$stderr})) {
                if([IO.File]::Exists($entry.path)) {
                    if((Get-Item -LiteralPath $entry.path).Length -le 4KB) {
                        $diagnostic[$entry.role]=(Read-InstallGuardFixtureOutput $entry.path).text
                    } else {$diagnostic[$entry.role]='output exceeds retained diagnostic bound'}
                }
            }
            if($holder -and $holder.HasExited){$diagnostic.exit_code=$holder.ExitCode}
        } catch {$diagnostic.diagnostic_failure=$_.Exception.Message}
        $receipt['installation_guard_holder_failure']=$diagnostic
        throw $guardFailure
    } finally {
        $cleanup=Complete-InstallGuardFixtureCleanup $holder $events $heldImage $launchAttempted $normalExit
        $script:installGuardHolderClosed=$cleanup.confirmed
        if(-not $cleanup.confirmed) {
            $message=[string]$cleanup.first_error
            $receipt['installation_guard_cleanup_failure']=$message.Substring(0,[Math]::Min(4096,$message.Length))
            if(-not $guardFailure){throw $cleanup.first_error}
        }
    }
}

// Copyright (c) 2024 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#include <common/src/common.h>
#line SOURCE_FILE("win/win_daemon.cpp")

#include "win_daemon.h"
#include "wfp_filters.h"
#include "win_appmanifest.h"
#include <common/src/win/win_winrtloader.h>
#include "win_interfacemonitor.h"
#include <common/src/builtin/path.h>
#include "../networkmonitor.h"
#include "win.h"
#include "brand.h"
#include <common/src/exec.h>
#include "../../../extras/installer/win/tap_inl.h"
#include "../../../extras/installer/win/util_inl.h" // getSystemTempPath()
#include <QDir>

#include <Msi.h>
#include <MsiQuery.h>
#include <WinDNS.h>

#pragma comment(lib, "Msi.lib")
#pragma comment(lib, "Dnsapi.lib")

#include <TlHelp32.h>
#include <Psapi.h>

namespace
{
    // Name and description for WFP filter rules
    wchar_t wfpFilterName[] = L"" PIA_PRODUCT_NAME " Firewall";
    wchar_t wfpFilterDescription[] = L"Implements privacy filtering features of " PIA_PRODUCT_NAME ".";
    wchar_t wfpProviderCtxName[] = L"" BRAND_SHORT_NAME " WFP Provider Context";
    wchar_t wfpProviderCtxDescription[] = L"" BRAND_SHORT_NAME " WFP Provider Context";
    wchar_t wfpCalloutName[] = L"" BRAND_SHORT_NAME " WFP Callout";
    wchar_t wfpCalloutDescription[] = L"" BRAND_SHORT_NAME " WFP Callout";

    // GUIDs of the callouts defined by the PIA WFP callout driver.  These must
    // match the callouts in the driver.  If you build a rebranded driver,
    // change the GUIDs in the driver and update these to match.  Otherwise,
    // keep the GUIDs for the PIA-branded driver.
    GUID PIA_WFP_CALLOUT_BIND_V4 = {0xb16b0a6e, 0x2b2a, 0x41a3, { 0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8 } };
    GUID PIA_WFP_CALLOUT_CONNECT_V4 = { 0xb80ca14a, 0xa807, 0x4ef2, { 0x87, 0x2d, 0x4b, 0x1a, 0x51, 0x82, 0x54, 0x2 } };
    GUID PIA_WFP_CALLOUT_FLOW_ESTABLISHED_V4 = { 0x18ebe4a1, 0xa7b4, 0x4b76, { 0x9f, 0x39, 0x28, 0x57, 0x1e, 0xaa, 0x6b, 0x6 } };
    GUID PIA_WFP_CALLOUT_CONNECT_AUTH_V4 = { 0xf6e93b65, 0x5cd0, 0x4b0d, { 0xa9, 0x4c, 0x13, 0xba, 0xfd, 0x92, 0xf4, 0x1c } };
    GUID PIA_WFP_CALLOUT_IPPACKET_INBOUND_V4 = { 0x6a564cd3, 0xd14e, 0x43dc, { 0x98, 0xde, 0xa4, 0x18, 0x14, 0x4d, 0x5d, 0xd2 } };
    GUID PIA_WFP_CALLOUT_IPPACKET_OUTBOUND_V4 = { 0xb06c0a5f, 0x2b58, 0x6753, { 0x85, 0x29, 0xad, 0x8f, 0x1c, 0x51, 0x5f, 0xf5 } };
}

WinUnbiasedDeadline::WinUnbiasedDeadline()
    : _expireTime{getUnbiasedTime()} // Initially expired
{
}

ULONGLONG WinUnbiasedDeadline::getUnbiasedTime() const
{
    ULONGLONG time;
    // Per doc, this can only fail if the pointer given is nullptr, which it's
    // not.
    ::QueryUnbiasedInterruptTime(&time);
    return time;
}

void WinUnbiasedDeadline::setRemainingTime(const std::chrono::microseconds &time)
{
    _expireTime = getUnbiasedTime();
    if(time > std::chrono::microseconds::zero())
    {
        // The unbiased interrupt time is in 100ns units, multiply by 10.
        _expireTime += static_cast<unsigned long long>(time.count()) * 10;
    }
}

std::chrono::microseconds WinUnbiasedDeadline::remaining() const
{
    ULONGLONG now = getUnbiasedTime();
    if(now >= _expireTime)
        return {};
    return std::chrono::microseconds{(_expireTime - now) / 10};
}

WinDaemon::WinDaemon(QObject* parent)
    : Daemon{parent},
      MessageWnd{WindowType::Invisible},
      _wfpCalloutMonitor{L"PiaWfpCallout"}
{
    kapps::net::FirewallConfig config{};
    config.daemonDataDir = Path::DaemonDataDir;
    config.resourceDir = Path::ResourceDir;
    config.executableDir = Path::ExecutableDir;
    config.productExecutables = std::vector<std::wstring>
        {
            Path::ClientExecutable,
            Path::DaemonExecutable,
            Path::OpenVPNExecutable,
            Path::SupportToolExecutable,
            Path::SsLocalExecutable,
            Path::WireguardServiceExecutable
        };
    config.resolverExecutables = std::vector<std::wstring>
        {
            Path::UnboundExecutable
        };
    config.brandInfo.pWfpFilterName = wfpFilterName;
    config.brandInfo.pWfpFilterDescription = wfpFilterDescription;
    config.brandInfo.pWfpProviderCtxName = wfpProviderCtxName;
    config.brandInfo.pWfpProviderCtxDescription = wfpProviderCtxDescription;
    config.brandInfo.pWfpCalloutName = wfpCalloutName;
    config.brandInfo.pWfpCalloutDescription = wfpCalloutDescription;

    config.brandInfo.wfpBrandProvider = BRAND_WINDOWS_WFP_PROVIDER;
    config.brandInfo.wfpBrandSublayer = BRAND_WINDOWS_WFP_SUBLAYER;

    config.brandInfo.wfpCalloutBindV4 = PIA_WFP_CALLOUT_BIND_V4;
    config.brandInfo.wfpCalloutConnectV4 = PIA_WFP_CALLOUT_CONNECT_V4;
    config.brandInfo.wfpCalloutFlowEstablishedV4 = PIA_WFP_CALLOUT_FLOW_ESTABLISHED_V4;
    config.brandInfo.wfpCalloutConnectAuthV4 = PIA_WFP_CALLOUT_CONNECT_AUTH_V4;
    config.brandInfo.wfpCalloutIppacketInboundV4 = PIA_WFP_CALLOUT_IPPACKET_INBOUND_V4;
    config.brandInfo.wfpCalloutIppacketOutboundV4 = PIA_WFP_CALLOUT_IPPACKET_OUTBOUND_V4;

    config.brandInfo.enableDnscache = [this](bool enable)
    {
        if(enable)
            _dnsCacheControl.restoreDnsCache();
        else
            _dnsCacheControl.disableDnsCache();
    };

    _pFirewall.emplace(config);

    // Qt for some reason passes Unix CA directories to OpenSSL by default on
    // Windows.  This results in the daemon attempting to load CA certificates
    // from C:\etc\ssl\, etc., which are not privileged directories on Windows.
    //
    // This seems to be an oversight.  QSslSocketPrivate::ensureCiphersAndCertsLoaded()
    // enables s_loadRootCertsOnDemand on Windows supposedly to permit fetching
    // CAs from Windows Update.  It's not clear how Windows would actually be
    // notified to fetch the certificates though, since Qt handles TLS itself
    // with OpenSSL.  The implementation of QSslCertificate::verify() does load
    // updated system certificates if this flag is set, but that still doesn't
    // mean that Windows would know to fetch a new root.
    //
    // Qt has already loaded the system CA certs as the default CAs by this
    // point, this just sets s_loadRootCertsOnDemand back to false to prevent
    // the Unix paths from being applied.
    //
    // This might break QSslCertificate::verify(), but PIA does not use this
    // since it is not provided on the Mac SecureTransport backend, we implement
    // this operation with OpenSSL directly.  Qt does not use
    // QSslCertificate::verify(), it's just provided for application use.  (It's
    // not part of the normal TLS connection establishment.)
    auto newDefaultSslConfig = QSslConfiguration::defaultConfiguration();
    newDefaultSslConfig.setCaCertificates(newDefaultSslConfig.caCertificates());
    QSslConfiguration::setDefaultConfiguration(newDefaultSslConfig);

    connect(&WinInterfaceMonitor::instance(), &WinInterfaceMonitor::interfacesChanged,
            this, &WinDaemon::checkTapAdapter);
    // Check the initial state now
    checkTapAdapter();

    // The network monitor never fails to load on Windows.
    Q_ASSERT(_pNetworkMonitor);
    // On Windows, firewall rules can change if the existing DNS servers change,
    // and the only way we can detect that is via general network changes.
    // The existing DNS server detection on Windows also depends on PIA's DNS
    // servers (since the information we can get from Windows is limited; see
    // findExistingDNS()), they are detected when applying firwall rules on
    // Windows.
    // Since the firewall rules also depend on PIA's applied DNS servers,
    connect(_pNetworkMonitor.get(), &NetworkMonitor::networksChanged,
            this, &WinDaemon::queueApplyFirewallRules);

    connect(&_wfpCalloutMonitor, &ServiceMonitor::serviceStateChanged, this,
            [this](StateModel::NetExtensionState extState)
            {
                state().netExtensionState(qEnumToString(extState));
            });
    state().netExtensionState(qEnumToString(_wfpCalloutMonitor.lastState()));
    qInfo() << "Initial callout driver state:" << state().netExtensionState();

    connect(this, &Daemon::aboutToConnect, this, &WinDaemon::onAboutToConnect);

    // _appMonitor.appIdsChanged() can be invoked on several different threads.
    // queueApplyFirewallRules() isn't thread safe, dispatch back to the main
    // thread.
    _appMonitor.appIdsChanged = [this]()
    {
        QMetaObject::invokeMethod(this, &Daemon::queueApplyFirewallRules,
                                  Qt::QueuedConnection);
    };

    // Split tunnel feature removed
    updateSplitTunnelRules();

    // Split tunnel feature removed - but still perform callout monitor checks
    _wfpCalloutMonitor.doManualCheck();

    // Split tunnel support errors are platform-dependent, nothing else adds
    // them (otherwise we'd have to do a proper get-append-set below)
    Q_ASSERT(_state.splitTunnelSupportErrors().empty());
    
    // We're marking split tunnel as unsupported since the feature is removed
    _state.splitTunnelSupportErrors({QStringLiteral("feature_removed")});
}

WinDaemon::~WinDaemon()
{
    qInfo() << "WinDaemon shutdown complete";
}

std::shared_ptr<NetworkAdapter> WinDaemon::getTapAdapter()
{
    // For robustness, when making a connection, we always re-query for the
    // network adapter, in case the change notifications aren't 100% reliable.
    // Also update the StateModel accordingly to keep everything in sync.
    auto adapters = WinInterfaceMonitor::getDescNetworkAdapters(L"Private Internet Access Network Adapter");
    if (adapters.size() == 0)
    {
        auto remainingGracePeriod = _resumeGracePeriod.remaining().count();
        qError() << "TAP adapter is not installed, grace period time:" << remainingGracePeriod;
        // The TAP adapter usually appears to be missing following an OS resume.
        // However, this doesn't mean it isn't installed, so only report it if
        // we're not in the post-resume grace period.
        state().tapAdapterMissing(remainingGracePeriod <= 0);
        return {};
    }
    // Note that we _don't_ reset the resume grace period if we _do_ find the
    // TAP adapter.  We usually end up checking a few times before the "resume"
    // notification is sent by the OS, so resetting the grace period could cause
    // those checks to show spurious errors (they're normally suppressed due to
    // entering the grace period after the "suspend" notification).
    state().tapAdapterMissing(false);
    return adapters[0];
}

std::shared_ptr<NetworkAdapter> WinDaemon::getTunAdapter()
{
    NET_LUID tunAdapterLuid{};

    if(!_wintunAdapter)
    {
        _wintunAdapter = _wintun.openAdapter(WintunData::pOpenVPNName);
        if(!_wintunAdapter)
        {
            qInfo() << "Failed to open adapter, will recreate it";
            _wintunAdapter = _wintun.recreateAdapter(WintunData::pOpenVPNName);
            if(!_wintunAdapter)
            {
                qError() << "Failed to create adapter" << WintunData::pOpenVPNName << "due to" << GetLastError();
                return {};
            }
        }
    }

    qDebug() << "WinTun adapter loaded bool" << !(!_wintunAdapter);
    qDebug() << "WinTun adapter loaded ptr get" << _wintunAdapter.get();
    qDebug() << "WinTun adapter loaded get" << _wintunAdapter->get();

    _wintun.getAdapterLuid(_wintunAdapter->get(), &tunAdapterLuid);
    qDebug() << "Retrieved luid" << tunAdapterLuid.Value;
    std::shared_ptr<NetworkAdapter> pTunAdapter;
    if(tunAdapterLuid.Value)
        pTunAdapter = WinInterfaceMonitor::getAdapterForLuid(tunAdapterLuid.Value);

    if(!pTunAdapter)
    {
        qWarning() << "Did not find any OpenVPN WinTUN adapter for LUID"
            << tunAdapterLuid.Value;
    }
    
    return pTunAdapter;
}

std::shared_ptr<NetworkAdapter> WinDaemon::recreateTunAdapter()
{
    _wintunAdapter = _wintun.recreateAdapter(WintunData::pOpenVPNName);
    if(!_wintunAdapter)
    {
        qWarning() << "Unable to create OpenVPN WinTUN adapter";
        return {};
    }

    NET_LUID tunAdapterLuid{};
    _wintun.getAdapterLuid(*_wintunAdapter, &tunAdapterLuid);
    std::shared_ptr<NetworkAdapter> pTunAdapter;
    if(tunAdapterLuid.Value)
        pTunAdapter = WinInterfaceMonitor::getAdapterForLuid(tunAdapterLuid.Value);

    if(!pTunAdapter)
    {
        qWarning() << "Created OpenVPN WinTUN adapter with LUID"
            << tunAdapterLuid.Value << "but could not find network interface";
    }

    return pTunAdapter;
}

void WinDaemon::checkTapAdapter()
{
    // To check the network adapter state, just call getNetworkAdapter() and let
    // it update DaemonState.  Ignore the result.
    getTapAdapter();
}

void WinDaemon::onAboutToConnect()
{
    // Reapply split tunnel rules.  If an app updates, the executables found
    // from the rules might change (likely for UWP apps because the package
    // install paths are versioned, less likely for native apps but possible if
    // the link target changes).
    //
    // If this does happen, this means the user may have to reconnect for the
    // updated rules to apply, but this is much better than restarting the
    // service or having to make a change to the rules just to force this
    // update.
    updateSplitTunnelRules();

    // If the WFP callout driver is installed but not loaded yet, load it now.
    // The driver is loaded this way for resiliency:
    // - Loading on boot would mean that a failure in the callout driver would
    //   render the system unbootable (bluescreen on boot)
    // - Loading on first client connect would prevent the user from seeing an
    //   advertised update or installing it
    //
    // This may slow down the first connection attempt slightly, but the driver
    // does not take long to load and the resiliency gains are worth this
    // tradeoff.

    // Do a manual check of the callout state right now if needed
    _wfpCalloutMonitor.doManualCheck();

    // Skip this quickly if the driver isn't installed to avoid holding up
    // connections (don't open SCM or the service an additional time).
    // TODO - Also check master toggle for split tunnel
    if(_wfpCalloutMonitor.lastState() == StateModel::NetExtensionState::NotInstalled)
    {
        qInfo() << "Callout driver hasn't been installed, nothing to start.";
        return;
    }

    qInfo() << "Starting callout driver";
    auto startResult = startCalloutDriver(10000);
    switch(startResult)
    {
        case ServiceStatus::ServiceNotInstalled:
            // Normally the check above should detect this.
            qWarning() << "Callout driver is not installed, but monitor is in state"
                << qEnumToString(_wfpCalloutMonitor.lastState());
            break;
        case ServiceStatus::ServiceAlreadyStarted:
            qInfo() << "Callout driver is already running";
            break;
        case ServiceStatus::ServiceStarted:
            qInfo() << "Callout driver was started successfully";
            break;
        case ServiceStatus::ServiceRebootNeeded:
            // TODO - Display this in the client UI
            qWarning() << "Callout driver requires system reboot";
            break;
        default:
            qWarning() << "Callout driver couldn't be started:" << startResult;
            break;
    }
}

LRESULT WinDaemon::proc(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg)
    {
    case WM_POWERBROADCAST:
        switch(wParam)
        {
        case PBT_APMRESUMEAUTOMATIC:
        case PBT_APMSUSPEND:
            // After the system resumes, allow 1 minute for the TAP adapter to
            // come back.
            //
            // This isn't perfectly reliable since it's a hard-coded timeout,
            // but there is no way to know at this point whether the TAP adapter
            // is really missing or if it's still coming back from the resume.
            // PBT_APMRESUMEAUTOMATIC typically occurs before the TAP adapter is
            // restored.  PBM_APMRESUMESUSPEND _seems_ to typically occur after
            // it is restored, but the doc indicates that this isn't sent in all
            // cases, we can't rely on it.
            //
            // This just suppresses the "TAP adapter missing" error, so the
            // failure modes are acceptable:
            // - if the adapter is really missing, we take 1 minute to actually
            //   show the error
            // - if the adapter is present but takes >1 minute to come back, we
            //   show the error incorrectly in the interim
            //
            // We also trigger the grace period for a suspend message, just in
            // case a connection attempt would occur between the suspend message
            // and the resume message.
            _resumeGracePeriod.setRemainingTime(std::chrono::minutes{1});
            checkTapAdapter();  // Check now in case we were showing the error already
            qInfo() << "OS suspend/resume:" << wParam;
            break;
        default:
            break;
        }
        return 0;

    default:
        return MessageWnd::proc(uMsg, wParam, lParam);
    }
}

void WinDaemon::applyFirewallRules(kapps::net::FirewallParams params)
{
    Q_ASSERT(_pFirewall);   // Class invariant
    params.excludeApps = _appMonitor.getExcludedAppIds();
    params.vpnOnlyApps = _appMonitor.getVpnOnlyAppIds();
    _pFirewall->applyRules(params);
}

QJsonValue WinDaemon::RPC_inspectUwpApps(const QJsonArray &familyIds)
{
    QJsonArray exeApps, wwaApps;

    for(const auto &family : familyIds)
    {
        auto installDirs = getWinRtLoader().adminGetInstallDirs(family.toString());
        AppExecutables appExes{};
        for(const auto &dir : installDirs)
        {
            if(!inspectUwpAppManifest(dir, appExes))
            {
                // Failed to scan a directory, skip this app, couldn't understand it
                appExes.executables.clear();
                appExes.usesWwa = false;
            }
        }

        if(appExes.usesWwa && appExes.executables.empty())
            wwaApps.push_back(family);
        else if(!appExes.usesWwa && !appExes.executables.empty())
            exeApps.push_back(family);
        else
        {
            // Otherwise, no targets were found, or both types of targets were
            // found, skip it.
            qInfo() << "Skipping app:" << family << "->" << appExes.executables.size()
                << "exes, uses wwa:" << appExes.usesWwa;
        }
    }

    QJsonObject result;
    result.insert(QStringLiteral("exe"), exeApps);
    result.insert(QStringLiteral("wwa"), wwaApps);
    return result;
}

void WinDaemon::RPC_checkDriverState()
{
    // Re-check the WFP callout state, this is only relevant on Win 10 1507
    _wfpCalloutMonitor.doManualCheck();
}

namespace
{
    const std::string sectDelim{"\r\n>>>  ["};
    const std::array<std::string, 3> setupapiLogPatterns
    {
        "wintun.inf",
        "pia-wgservice.exe",
        "tap-pia-0901.sys"
    };
}

QByteArray filterSetupapiDevLog(const QByteArray &log)
{
    QByteArray filtered;
    filtered.reserve(log.size());

    // The log sections all look roughly like:
    //
    // >>>  [Device Install (Install Windows Update driver) - pci\ven_1002&dev_4385]
    // >>>  Section start 2021/04/22 12:06:16.123
    //      ...details...
    // <<<  Section end 2021/04/22 12:06:52.004
    // <<<  [Exit status: SUCCESS]
    //
    // In other words:
    // - a line describing the action occurring in square brackets
    // - start time (in local time)
    // - details of the action (usually starts with indentation but can have a
    //   leading '!' for warnings/errors)
    // - end time
    // - exit status
    //
    // So split up the log into sections starting with '\r\n>>>  [', check if each
    // section is relevant, and include only relevant sections.  Note that
    // 'log' was limited to the last 10K lines of setupapi.dev.log, since it
    // might be huge.
    auto itLogBegin = log.begin();
    auto itLogEnd = log.end();
    auto itSectStart = std::search(itLogBegin, itLogEnd, sectDelim.begin(),
                                   sectDelim.end());
    while(itSectStart != itLogEnd)
    {
        auto itNextSectStart = std::search(itSectStart+1, itLogEnd,
                                           sectDelim.begin(), sectDelim.end());

        // If any pattern matches this section, include it.
        if(std::any_of(setupapiLogPatterns.begin(), setupapiLogPatterns.end(),
            [&](const std::string &ptn)
            {
                return std::search(itSectStart, itNextSectStart,
                                   ptn.begin(), ptn.end()) != itNextSectStart;
            }))
        {
            filtered.append(itSectStart, static_cast<int>(itNextSectStart-itSectStart));
        }

        itSectStart = itNextSectStart;
    }

    return filtered;
}

void WinDaemon::writePlatformDiagnostics(DiagnosticsFile &file)
{
    file.writeCommand("OS Version", "wmic", QStringLiteral("os get Caption,CSDVersion,BuildNumber,Version /value"));
    file.writeText("Overview", diagnosticsOverview());
    file.writeCommand("Interfaces (ipconfig)", "ipconfig", QStringLiteral("/all"));
    file.writeCommand("Routes (netstat -nr)", "netstat", QStringLiteral("-nr"));
    file.writeCommand("DNS configuration", "netsh", QStringLiteral("interface ipv4 show dnsservers"));

    for(const auto &adapter : WinInterfaceMonitor::getNetworkAdapters())
    {
        auto index = adapter->indexIpv4();
        file.writeCommand(QStringLiteral("Interface info (index=%1)").arg(index), "netsh", QStringLiteral("interface ipv4 show interface %1").arg(index));
    }

    // WFP (windows firewall) filter information. We need to process it as the raw data is XML.
    file.writeCommand("WFP filters", "netsh", QStringLiteral("wfp show filters dir = out file = -"),
        [](const QByteArray &output) { return WfpFilters(output).render(); });

    // GPU and driver info - needed to attempt to reproduce graphical issues
    // on Windows (which are pretty common due to poor OpenGL support)
    file.writeCommand("Graphics drivers", "wmic", QStringLiteral("path win32_VideoController get /format:list"));
    file.writeCommand("Network adapters", "wmic", QStringLiteral("path win32_NetworkAdapter get /format:list"));
    file.writeCommand("Network drivers", "wmic", QStringLiteral("path win32_PnPSignedDriver where 'DeviceClass=\"NET\"' get /format:list"));

    // Collect relevant parts of setupapi.dev.log.  This is important for
    // troubleshooting driver installation errors, such as:
    // - TAP installation or configuration errors
    // - WinTUN installation errors (note that WireGuard creates a WinTUN
    //   device instance at connection time, so this can manifest as a
    //   connection failure rather than an install issue).
    //
    // setupapi.dev.log can be huge and contains a lot that we don't really
    // care about, so try to filter this down just to sections relevant to PIA
    // drivers.
    file.writeCommand("SetupAPI device log (PIA drivers)", "powershell.exe",
        QStringLiteral(R"(/C Get-Content -Tail 10000 "$env:WINDIR\INF\setupapi.dev.log")"),
        &filterSetupapiDevLog);

    // Raw WFP filter dump, important to identify app rules (and other rules
    // that may affect the same apps) for split tunnel on Windows
    file.writeCommand("WFP filters (raw)", "netsh", QStringLiteral("wfp show filters dir = out verbose = on file = -"));

    // WFP events dumps for each excluded app.  Can diagnose issues with split
    // tunnel app rules.
    _appMonitor.dump();
    const auto &excludedApps = _appMonitor.getExcludedAppIds();
    int i=0;
    for(const auto &pAppId : excludedApps)
    {
        Q_ASSERT(pAppId);   // Guarantee of WinAppMonitor::getAppIds()

        const auto &appId = qs::toQString(pAppId->printableString());
        auto title = QStringLiteral("WFP events (bypass %1 - %2)").arg(i).arg(appId);
        auto cmdParams = QStringLiteral("wfp show netevents appid = \"%1\" file = -").arg(appId);
        file.writeCommand(title, "netsh", cmdParams);
        ++i;
    }
    const auto &vpnOnlyApps = _appMonitor.getVpnOnlyAppIds();
    i=0;
    for(const auto &pAppId : vpnOnlyApps)
    {
        Q_ASSERT(pAppId);   // Guarantee of WinAppMonitor::getAppIds()

        const auto &appId = qs::toQString(pAppId->printableString());
        auto title = QStringLiteral("WFP events (VPN-only %1 - %2)").arg(i).arg(appId);
        auto cmdParams = QStringLiteral("wfp show netevents appid = \"%1\" file = -").arg(appId);
        file.writeCommand(title, "netsh", cmdParams);
        ++i;
    }

    // Wireguard logs
    file.writeCommand("WireGuard Logs", Path::WireguardServiceExecutable,
                      QStringList{QStringLiteral("/dumplog"), Path::ConfigLogFile});

    // Whether the official WireGuard app is installed - it can sometimes cause problems
    QString wgAppExe = Path::getProgramsFolder() / QStringLiteral("WireGuard") / QStringLiteral("WireGuard.exe");
    file.writeText("Official WireGuard App installed", QFile::exists(wgAppExe) ? "yes" : "no");

    // Installed and running drivers (buggy drivers may prevent TAP installation)
    file.writeCommand("Drivers", QStringLiteral("driverquery"), {QStringLiteral("/v")});

    // DNS
    file.writeCommand("Resolve-DnsName (www.pia.com)", "powershell.exe", QStringLiteral("/C Resolve-DnsName www.privateinternetaccess.com"));
    file.writeCommand("Resolve-DnsName (-Server piadns www.pia.com)", "powershell.exe", QStringLiteral("/C Resolve-DnsName www.privateinternetaccess.com -Server %1").arg(piaModernDnsVpn()));
    file.writeCommand("ping (ping www.pia.com)", "ping", QStringLiteral("www.privateinternetaccess.com /w 1000 /n 1"));
    file.writeCommand("ping (ping piadns)", "ping", QStringLiteral("%1 /w 1000 /n 1").arg(piaModernDnsVpn()));

    auto installLog = getSystemTempPath();
    // It's possible that getSystemTempPath() could fail if TEMP was not set in
    // system variables for some reason.  Leave installLog empty rather than
    // trying to read '/pia-install.log'
    if(!installLog.empty())
        installLog += L"\\" BRAND_CODE "-install.log";

    file.writeCommand("Installer log", "cmd.exe",
        QString::fromStdWString(LR"(/C "type ")" + installLog + LR"("")"));
}

void WinDaemon::applyPlatformInstallFeatureFlags()
{
     // The default OpenVPN network adapter was changed to WinTUN in 2.11.
    // If any significant issues occur in the field, we can publish this
    // feature flag to revert to TAP by default.
    if(_data.hasFlag(QStringLiteral("install_win_use_tap")))
    {
        qInfo() << "Applying install_win_use_tap feature flag, install and select TAP";
        // We need to install the TAP driver now, as it's not part of the
        // default installation in 2.11.  Note that we are currently in session
        // 0, not a user session, so this is not able to prompt for approval.
        // The TAP adapter for Windows 10+ is WHQL-signed, so approval
        // shouldn't be needed.  If the install fails we'll stay on WinTUN,
        // this is sufficient for a failsafe feature flag.
        int installResult = Exec::cmd(Path::DaemonExecutable, {QStringLiteral("tap"), QStringLiteral("install")});
        qInfo() << "TAP installation completed with result" << installResult;
        switch(installResult)
        {
            case DriverStatus::DriverUpdated:
            case DriverStatus::DriverUpdateNotNeeded:
            case DriverStatus::DriverInstalled:
            case DriverStatus::DriverUninstalled:
                qInfo() << "TAP installation succeeded, select TAP now";
                _settings.windowsIpMethod(QStringLiteral("dhcp"));
                break;
            case DriverStatus::DriverUpdatedReboot:
            case DriverStatus::DriverInstalledReboot:
            case DriverStatus::DriverUninstalledReboot:
                // This is rare on modern Windows.  The client does have a
                // "reboot needed" notification but we would need to add more
                // state to indicate this state, it's not really worth it for
                // such a rare corner case of a failsafe - just stay on WinTUN.
                qInfo() << "TAP installation requires reboot, not selecting TAP now";
                break;
            default:
                qWarning() << "TAP installation failed, not selecting TAP now";
                break;
        }
    }
}

void WinDaemon::updateSplitTunnelRules()
{
    // Try to load the link reader; this can fail.
    nullable_t<kapps::core::WinLinkReader> linkReader;
    try
    {
        linkReader.emplace();
    }
    catch(const std::exception &ex)
    {
        qWarning() << "Unable to resolve shell links -" << ex.what();
        // Eat error and continue
    }

    // Split tunnel feature removed - this is a no-op method now
    // We still create the AppExecutables structures but they remain empty
    AppExecutables excludedExes;
    AppExecutables vpnOnlyExes;

    _appMonitor.setSplitTunnelRules(excludedExes.executables, vpnOnlyExes.executables);
}

class TraceMemSize : public kapps::core::OStreamInsertable<TraceMemSize>
{
public:
    TraceMemSize(std::size_t mem) : _mem{mem} {}

public:
    void trace(std::ostream &os) const
    {
        const std::array<const char *, 3> units
        {{
            "B",
            "KiB",
            "MiB"
        }};

        int unitIdx{0};
        std::size_t memInUnits{_mem};
        while(unitIdx+1 < units.size() && memInUnits > 1024)
        {
            ++unitIdx;
            memInUnits /= 1024;
        }

        os << memInUnits << ' ' << units[unitIdx];
    }

private:
    std::size_t _mem;
};

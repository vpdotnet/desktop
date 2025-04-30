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
#line SOURCE_FILE("linux_nl.cpp")

#include "linux_nl.h"
#include "linux_nlcache.h"
#include "linux_nl80211.h"
#include "linux_genlfamilies.h"
#include "linux_libnl.h"
#include <QMetaObject>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>

class LinuxNl::Worker
{
private:
    enum PollIdx : size_t
    {
        KillSocket,
        RouteSocket,
        GenlFamiliesSocket,
        Nl80211Socket,
        Count
    };

public:
    // A parent reference is provided to queue calls back to the main thread (no
    // other members should be used; this class works on the worker thread)
    //
    // Worker takes ownership of the kill socket.
    explicit Worker(LinuxNl &parent, kapps::core::PosixFd killSocket);

private:
    // Read the current state of the caches and send state to main thread
    void readCaches();

    // Wrappers to receive events for each socket - if revents is nonzero,
    // passes it to the appropriate socket, then checks for updates to the data
    // in the appropriate cache(s).  Clears revents.
    void receiveRoute(short &revents);
    void receiveGenlFamilies(short &revents);
    void receiveNl80211(short &revents);

public:
    // Wait for events to be signaled, then receive them.
    // If the kill socket is signaled, this returns false to terminate the event
    // loop.  Otherwise, returns true to continue the event loop.
    bool receive();

private:
    LinuxNl &_parent;
    // poll configurations - includes kill socket and all netlink sockets
    std::array<pollfd, PollIdx::Count> _pollCfgs;
    // Kill socket - terminates the event loop when signaled
    kapps::core::PosixFd _killSocket;
    // Socket for all "route" caches - link/address/route
    LinuxNlCacheSock _routeSock;
    // Cache of generic netlink families - used to detect when nl80211 is added
    // or removed (and its ID and multicast groups)
    LinuxGenlFamilies _genlFamilies;
    // Fixed caches - these are always valid
    std::shared_ptr<LinuxNlCache> _pLinkCache;
    std::shared_ptr<LinuxNlCache> _pAddrCache;
    std::shared_ptr<LinuxNlCache> _pRouteCache;
    // nl80211 socket and cache - created dynamically when the nl80211 generic
    // netlink family is present.  This is nullptr when nl80211 isn't present.
    std::unique_ptr<LinuxNl80211Cache> _p80211Cache;
    // The last emitted connections are cached in order to ignore irrelevant/
    // duplicate events.  These are sorted and checked in readCaches().
    std::vector<NetworkConnection> _lastConnections;
};

LinuxNl::Worker::Worker(LinuxNl &parent, kapps::core::PosixFd killSocket)
    : _parent{parent}, _pollCfgs{}, _killSocket{std::move(killSocket)},
      _routeSock{NETLINK_ROUTE}
{
    _pollCfgs[PollIdx::KillSocket].fd = _killSocket.get();
    _pollCfgs[PollIdx::RouteSocket].fd = _routeSock.getFd();
    _pollCfgs[PollIdx::GenlFamiliesSocket].fd = _genlFamilies.getFd();
    _pollCfgs[PollIdx::Nl80211Socket].fd = kapps::core::PosixFd::Invalid; // Set on nl80211 cache creation

    for(auto &cfg : _pollCfgs)
    {
        cfg.events = POLLIN;
        cfg.revents = 0;
    }

    // If we couldn't connect to netlink (above) or if any of the caches below
    // can't be constructed, Worker can't be created - these throw and
    // runOnWorkerThread() ends the worker thread.
    //
    // The client continues to operate normally, it just can't detect any
    // networks in that case.
    _pLinkCache = _routeSock.addCache("route/link", {RTNLGRP_LINK},
                                      {RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK,
                                       RTM_SETLINK});
    _pLinkCache->provide(); // Required by address cache
    _pAddrCache = _routeSock.addCache("route/addr",
                                      {RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR},
                                      {RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR});
    _pRouteCache = _routeSock.addCache("route/route",
                                       {RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE,
                                        RTNLGRP_DECnet_ROUTE}, // Just to stay in sync with libnl
                                       {RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE});

    // Don't report anything yet, because the _genlFamilies cache definitely
    // isn't ready yet (it fills asynchronously).  Note that older distributions
    // tend to report an "initial change" for the route cache immediately, but
    // newer distributions do not - we can't rely on getting any changes for the
    // route cache.
    //
    // In our case though, since the genl cache fills asynchronously, it'll
    // trigger our initial state notification when it becomes ready.
}

bool readNlAddr(libnl::nl_addr *pNlAddr, std::size_t valueSize, void *pValue)
{
    if(!pNlAddr || libnl::nl_addr_get_len(pNlAddr) != valueSize)
        return false;

    void *pAddrData = libnl::nl_addr_get_binary_addr(pNlAddr);
    if(!pAddrData)
        return false;

    std::memcpy(pValue, pAddrData, valueSize);
    return true;
}

kapps::core::Ipv4Address readNlAddr4(libnl::nl_addr *pNlAddr)
{
    quint32 ipv4Value{};
    if(readNlAddr(pNlAddr, sizeof(ipv4Value), &ipv4Value))
    {
        // Note - ntohl() could be either a macro or function (so don't qualify
        // with ::) - and this seems to depend on the order of inclusion of
        // arpa/inet.h vs. netinet/in.h, which is especially hard to control in
        // combined compilation.
        ipv4Value = ntohl(ipv4Value);
        return {ipv4Value};
    }

    return {};
}

kapps::core::Ipv6Address readNlAddr6(libnl::nl_addr *pNlAddr)
{
    quint8 ipv6Value[16]{};
    if(readNlAddr(pNlAddr, sizeof(ipv6Value), ipv6Value))
        return {ipv6Value};

    return {};
}

// Returns true if pRoute is a default route
// We identify a route as default if its destination has 0 length or equals 0.0.0.0/0.
bool isDefaultRoute(libnl::rtnl_route *pRoute)
{
    libnl::nl_addr *pDest = libnl::rtnl_route_get_dst(pRoute);

    // Not a default route if it doesn't have a destination address somehow. 
    // This is a sanity check and should not happen.
    if (!pDest)
        return false;

    // The destination address has zero length.
    if (libnl::nl_addr_get_len(pDest) == 0)
        return true;

    // Matches 0.0.0.0/0
    // Some routes will have destination 0.0.0.0 but a prefix != 0 (e.g. the openvpn tunnel interface).
    // Those are not default routes here, so we will return false.
    return libnl::nl_addr_iszero(pDest) && libnl::nl_addr_get_prefixlen(pDest) == 0;
}

// Check if pRoute is a default-gateway route, and return the gateway if it is.
// Looks for a route with all of the following:
// - in the main routing table
// - a zero-length destination address (indicates a default route)
// - a next-hop that has a gateway address (and interface index)
//
// Only the main routing table is considered when looking for gateways.  PIA
// wants to know what the default gateway/interface is, which is the
// lowest-metric default route in the main routing table.  Technically this
// makes some assumptions about how routing rules are set up, but this has
// worked fine in the field.
//
// If all of these hold, sets ifIndex to the next-hop interface index and
// returns the next-hop gateway.  Otherwise, returns nullptr.
libnl::nl_addr *getNlRouteGateway(libnl::rtnl_route *pRoute, int &ifIndex)
{
    if(!pRoute)
        return nullptr;

    // Is this route in the main routing table?
    uint32_t table = libnl::rtnl_route_get_table(pRoute);
    if(table != RT_TABLE_MAIN)
        return nullptr; // Not in the main routing table, don't care

    if(!isDefaultRoute(pRoute))
        return nullptr;

    // We don't support network detection in the presence of multipath routing.
    // If there isn't exactly 1 next-hop address, ignore this route.
    //
    // Note that we _do_ support multiple default gateways when they are not
    // multipath-routed, like multiple independent network connections - each
    // connection has its own gateway and can deduce a network identifier.
    // Those appear as separate routes with 1 next-hop gateway each.
    //
    // Multiple next-hops are used to load-balance across multiple independent
    // routes; that's the configuration we do not support for network detection
    // right now.
    if(libnl::rtnl_route_get_nnexthops(pRoute) != 1)
        return nullptr;

    libnl::rtnl_nexthop *pNextHop = libnl::rtnl_route_nexthop_n(pRoute, 0);
    libnl::nl_addr *pGateway = libnl::rtnl_route_nh_get_gateway(pNextHop);
    if(!pGateway)
        return nullptr;

    ifIndex = libnl::rtnl_route_nh_get_ifindex(pNextHop);
    return pGateway;
}

void LinuxNl::Worker::readCaches()
{
    // The various pieces of data that we need are reported separately.
    // Assemble them using interface IDs, then look up the interface IDs to find
    // the interface names.
    struct RawInterfaceData
    {
        // All of these objects are owned by the various netlink caches; these
        // values are only held locally here in readCaches().  Any of these
        // addresses can be nullptr.
        std::vector<libnl::nl_addr*> _addrs4;
        std::vector<libnl::nl_addr*> _addrs6;
        libnl::nl_addr *_pIpv4Gateway;
        libnl::nl_addr *_pIpv6Gateway;
    };

    // Keys are interface IDs.
    std::unordered_map<int, RawInterfaceData> interfaceAddrs;
    interfaceAddrs.reserve(_pAddrCache->count());   // Reserve using this upper bound
    for(const auto &pObj : *_pAddrCache)
    {
        // libnl uses crude "declare all the same members" inheritance, these
        // are really rtnl_addr objects
        auto pAddr = reinterpret_cast<libnl::rtnl_addr*>(pObj);

        // Get the interface index
        int ifindex = libnl::rtnl_addr_get_ifindex(pAddr);
        // Get the local address
        libnl::nl_addr *pLocal = libnl::rtnl_addr_get_local(pAddr);
        // Is it IPv4 or IPv6?
        int family = pLocal ? libnl::nl_addr_get_family(pLocal) : AF_UNSPEC;
        switch(family)
        {
            case AF_INET:
                interfaceAddrs[ifindex]._addrs4.push_back(pLocal);
                break;
            case AF_INET6:
                interfaceAddrs[ifindex]._addrs6.push_back(pLocal);
                break;
            default:
                // Something else, don't care
                break;
        }
    }

    // Keep track of the default route with the lowest metric to determine the
    // default interface, for each of IPv4 and IPv6.
    struct DefaultGateway
    {
        std::uint32_t metric;
        int ifindex; // -1 indicates we haven't observed a default route yet
    } lowestGateway4{0, -1}, lowestGateway6{0, -1};

    // Look for default gateway routes and add them to the connection info
    for(const auto &pObj : *_pRouteCache)
    {
        // These are rtnl_route objects
        auto pRoute = reinterpret_cast<libnl::rtnl_route*>(pObj);

        int ifindex{};
        libnl::nl_addr *pGateway = getNlRouteGateway(pRoute, ifindex);

        if(!pGateway)
            continue;

        auto itItfAddrs = interfaceAddrs.find(ifindex);
        // It does sometimes happen that we get routes from libnl for
        // interfaces that no longer exist.  Specifically, this has been
        // observed with a USB Ethernet adapter by unplugging USB while it
        // is connected to a network.
        //
        // It seems the IPv4 gateway route is removed in this case (the
        // kernel no longer returns it in dumps), but no "delete route"
        // notification is sent.  (The IPv6 gateway route deletion is sent
        // correctly.)  It's not clear why this happens, but the route no
        // longer matters anyway since the interface is gone, and libnl
        // resyncs the next time it dumps IPv4 routes (which happens pretty
        // frequently), so it should not cause accumulation of memory even
        // if it happens a lot.
        if(itItfAddrs == interfaceAddrs.end())
            continue;

        // Get the metric (called "priority" by the kernel, "metrics" are other
        // parameters)
        std::uint32_t metric = libnl::rtnl_route_get_priority(pRoute);
        int family = libnl::rtnl_route_get_family(pRoute);
        switch(family)
        {
            case AF_INET:
                itItfAddrs->second._pIpv4Gateway = pGateway;
                if(lowestGateway4.ifindex == -1 || metric < lowestGateway4.metric)
                    lowestGateway4 = {metric, ifindex};
                break;
            case AF_INET6:
                itItfAddrs->second._pIpv6Gateway = pGateway;
                if(lowestGateway6.ifindex == -1 || metric < lowestGateway6.metric)
                    lowestGateway6 = {metric, ifindex};
                break;
            default:
                // Something else, don't care
                break;
        }
    }

    // Get the nl80211 state too
    // emptyWifi is used as a default if the 802.11 cache hasn't been created
    // (because the nl80211 family doesn't exist yet in the kernel)
    static const std::map<std::uint32_t, LinuxNl80211Cache::WifiStatus> emptyWifi{};
    const auto &wifiInterfaces = _p80211Cache ? _p80211Cache->interfaces() : emptyWifi;

    // Build NetworkConnection objects
    std::vector<NetworkConnection> connections;
    connections.reserve(interfaceAddrs.size());
    for(const auto &itfAddrs : interfaceAddrs)
    {
        // Look up the link using the interface index to get the interface name
        // This retains the link, so we have to release it later
        NlUniquePtr<libnl::rtnl_link> pItfLink{libnl::rtnl_link_get(_pLinkCache->get(), itfAddrs.first)};
        QString itfName;
        unsigned mtu{0};
        if(pItfLink)
        {
            itfName = QString::fromUtf8(libnl::rtnl_link_get_name(pItfLink.get()));
            mtu = libnl::rtnl_link_get_mtu(pItfLink.get());
        }

        std::vector<std::pair<kapps::core::Ipv4Address, unsigned>> addressesIpv4;
        addressesIpv4.reserve(itfAddrs.second._addrs4.size());
        for(const auto &pNlAddr4 : itfAddrs.second._addrs4)
        {
            kapps::core::Ipv4Address addr4 = readNlAddr4(pNlAddr4);
            if(addr4 != kapps::core::Ipv4Address{})
                addressesIpv4.push_back({addr4, libnl::nl_addr_get_prefixlen(pNlAddr4)});
        }

        std::vector<std::pair<kapps::core::Ipv6Address, unsigned>> addressesIpv6;
        addressesIpv6.reserve(itfAddrs.second._addrs6.size());
        for(const auto &pNlAddr6 : itfAddrs.second._addrs6)
        {
            kapps::core::Ipv6Address addr6 = readNlAddr6(pNlAddr6);
            if(addr6 != kapps::core::Ipv6Address{})
                addressesIpv6.push_back({addr6, libnl::nl_addr_get_prefixlen(pNlAddr6)});
        }

        // Linux does not have separate IPv4 and IPv6 MTUs; it's just set once
        // for the link.
        connections.push_back(NetworkConnection{itfName,
                                                NetworkConnection::Medium::Unknown,
                                                itfAddrs.first == lowestGateway4.ifindex,
                                                itfAddrs.first == lowestGateway6.ifindex,
                                                readNlAddr4(itfAddrs.second._pIpv4Gateway),
                                                readNlAddr6(itfAddrs.second._pIpv6Gateway),
                                                std::move(addressesIpv4),
                                                std::move(addressesIpv6),
                                                mtu, mtu});

        // If the interface is known to nl80211, it's a Wi-Fi interface.
        // Otherwise, assume that it's wired.  This isn't precisely correct for
        // other interfaces like cellular modems, etc., but it's reasonable.
        auto itWifi = wifiInterfaces.find(itfAddrs.first);
        if(itWifi == wifiInterfaces.end())
        {
            connections.back().medium(NetworkConnection::Medium::Wired);
        }
        else
        {
            connections.back().medium(NetworkConnection::Medium::WiFi);
            if(itWifi->second.associated)
            {
                connections.back().wifiAssociated(true);
                connections.back().parseWifiSsid(reinterpret_cast<const char *>(itWifi->second.ssid),
                                                itWifi->second.ssidLength);
                connections.back().wifiEncrypted(itWifi->second.encrypted);
            }
        }
    }

    // If the set of network connections hasn't changed, ignore this update.
    // We seem to get a lot of irrelevant traffic on the route socket, so this
    // is important to ignore all those updates, in particular to avoid
    // generating lots of noise in logs.
    std::sort(connections.begin(), connections.end());
    if(connections == _lastConnections)
    {
        // No change - nothing to report.  Don't trace, this happens a lot.
        return;
    }
    // Save a copy of the current connections
    _lastConnections = connections;

    qInfo() << "Reporting" << connections.size() << "networks:";
    int i=0;
    for(const auto &conn : connections)
    {
        qInfo() << "-" << i << "-" << conn;
        ++i;
    }

    // Dispatch this update over to the main thread
    // Capture the parent reference in the lambda, not this
    auto &localParent = _parent;
    QMetaObject::invokeMethod(&localParent,
        [&localParent, connections = std::move(connections)]()
        {
            localParent.networksUpdated(connections);
        }, Qt::QueuedConnection);
}

void LinuxNl::Worker::receiveRoute(short &revents)
{
    if(revents)
    {
        _routeSock.receive(revents);
        revents = 0;
    }
}

void LinuxNl::Worker::receiveGenlFamilies(short &revents)
{
    // Skip if zero
    if(!revents)
        return;

    _genlFamilies.receive(revents);
    revents = 0;

    const auto *pNl80211Family = _genlFamilies.getFamily(QStringLiteral(NL80211_GENL_NAME));
    // Get the group IDs if the family and group exist, or 0 otherwise.
    // 0 isn't a valid multicast group ID.
    int configGroupId = 0;
    int mlmeGroupId = 0;
    if(pNl80211Family)
    {
        const auto &mcastGroups = pNl80211Family->_multicastGroups;
        auto itConfigGroup = mcastGroups.find(QStringLiteral(NL80211_MULTICAST_GROUP_CONFIG));
        if(itConfigGroup != mcastGroups.end())
            configGroupId = itConfigGroup->second;
        auto itMlmeGroup = mcastGroups.find(QStringLiteral(NL80211_MULTICAST_GROUP_MLME));
        if(itMlmeGroup != mcastGroups.end())
            mlmeGroupId = itMlmeGroup->second;
    }


    // If we have a cache; we might need to destroy it if nl80211 is gone or
    // the protocol IDs have changed
    if(_p80211Cache)
    {
        if(!pNl80211Family ||
            pNl80211Family->_protocol != _p80211Cache->nl80211Protocol() ||
            configGroupId != _p80211Cache->configGroup() ||
            mlmeGroupId != _p80211Cache->mlmeGroup())
        {
            // nl80211 or config group is gone, or IDs changed, destroy cache
            _p80211Cache.reset();
            _pollCfgs[PollIdx::Nl80211Socket].fd = kapps::core::PosixFd::Invalid;
        }
    }

    // If we don't have a cache (including if it was destroyed above), and
    // we have all the protocol IDs, create a cache
    if(!_p80211Cache && pNl80211Family && configGroupId && mlmeGroupId)
    {
        qInfo() << "Creating nl80211 cache (protocol"
            << pNl80211Family->_protocol << "- config grp" << configGroupId
            << "- mlme grp" << mlmeGroupId << ")";
        _p80211Cache.reset(new LinuxNl80211Cache{pNl80211Family->_protocol,
                                                    configGroupId,
                                                    mlmeGroupId});
        _pollCfgs[PollIdx::Nl80211Socket].fd = _p80211Cache->getFd();
    }
}

void LinuxNl::Worker::receiveNl80211(short &revents)
{
    if(!revents)
        return;

    if(_p80211Cache)
    {
        qInfo() << "Receiving nl80211 events";
        _p80211Cache->receive(revents);
    }
    revents = 0;
}

bool LinuxNl::Worker::receive()
{
    errno = 0;
    if(::poll(_pollCfgs.data(), _pollCfgs.size(), -1) >= 0)
    {
        // Check sockets
        if(_pollCfgs[PollIdx::KillSocket].revents)
        {
            // Kill socket was signaled (or an error occurred on it)
            // End the thread
            qInfo() << "Netlink worker exiting:" << _pollCfgs[PollIdx::KillSocket].revents;
            return false;
        }

        // This can also throw if the netlink socket is lost for any reason,
        // which ends the worker thread
        receiveRoute(_pollCfgs[PollIdx::RouteSocket].revents);
        receiveGenlFamilies(_pollCfgs[PollIdx::GenlFamiliesSocket].revents);
        receiveNl80211(_pollCfgs[PollIdx::Nl80211Socket].revents);

        // If everything is ready, read caches and report updates.  If anything
        // is not ready, do not report any updates (but do not wipe out the
        // existing network configs, e.g. in case a Wi-Fi adapter has been
        // plugged in for the first time and we are just now dumping nl80211 for
        // the first time).
        if(!_genlFamilies.ready())
        {
            qInfo() << "Can't report networks yet, genlfamilies is not ready";
        }
        // If the 802.11 cache doesn't exist right now, but genlfamilies is
        // ready, that's fine, nl80211 just doesn't exist.  But if it does
        // exist, we have to wait until it's ready before reporting any more
        // updates.
        else if(_p80211Cache && !_p80211Cache->ready())
        {
            qInfo() << "Can't report networks yet, nl80211 is not ready";
        }
        else
        {
            // Everything is ready, report
            readCaches();
        }
    }
    else if(errno != EINTR)
    {
        // EINTR indicates a signal while polling - don't care about that,
        // just loop.  Other errors are fatal.
        qError() << "Terminating netlink worker due to poll error:" << errno;
        throw std::runtime_error{"Netlink worker poll error"};
    }

    // Either successful poll or EINTR - continue receiving events
    return true;
}

void LinuxNl::runOnWorkerThread(LinuxNl *pThis,
                                std::promise<kapps::core::PosixFd> killSocketPromise)
{
    // Note that this function is on the worker thread, so we shouldn't access
    // members of pThis, just use it to queue signals back to the main thread
    // (which is why pThis is passed as a parameter to a static function).

    int killSockets[2]{kapps::core::PosixFd::Invalid, kapps::core::PosixFd::Invalid};
    auto spResult = ::socketpair(AF_UNIX, SOCK_STREAM, 0, killSockets);
    // Provide the socket handle back to the main thread even if ::socketpair()
    // failed.  The main thread now owns it (using PosixFd).
    killSocketPromise.set_value(kapps::core::PosixFd{killSockets[1]});

    // This thread owns the other handle.
    kapps::core::PosixFd killSocket{killSockets[0]};

    if(spResult || !killSocket)
    {
        qError() << "Couldn't initialize netlink worker thread:"
            << "spResult:" << spResult
            << "killSocket:" << killSocket.get();
        return;
    }

    try
    {
        // This may throw if libnl fails to connect, fails to create any caches,
        // etc.
        Worker worker{*pThis, std::move(killSocket)};

        // Receive events until the worker tells us to quit, or an exception is
        // thrown
        while(worker.receive());

        // Normal termination, don't need to wipe out networks below
        return;
    }
    catch(LibnlError &ex)
    {
        qWarning() << "Netlink thread terminating, network information will not be available -"
            << ex;
    }
    catch(std::exception &ex)
    {
        qWarning() << "Netlink thread terminating, network information will not be available -"
            << ex.what();
    }

    // Since the worker is terminating abnormally, wipe out any networks we
    // previously reported.  If we lose the netlink socket(s), etc. after
    // reporting networks, this ensures we degrade gracefully rather than
    // possibly using stale network connections.
    QMetaObject::invokeMethod(pThis,
        [pThis]()
        {
            pThis->networksUpdated({});
        }, Qt::QueuedConnection);
}

LinuxNl::LinuxNl()
{
    std::promise<kapps::core::PosixFd> killSocketPromise;
    _workerKillSocket = killSocketPromise.get_future();

    _workerThread = std::thread{&LinuxNl::runOnWorkerThread, this,
                                std::move(killSocketPromise)};
}

LinuxNl::~LinuxNl()
{
    qDebug() << "Signaling netlink worker to terminate";
    // Terminate the run loop by writing to the kill socket.  If the worker
    // thread is still starting, this blocks until it provides the kill socket.
    unsigned char term = 0;
    kapps::core::PosixFd killSocket = _workerKillSocket.get();
    if(killSocket) {
        ssize_t result = ::write(killSocket.get(), &term, sizeof(term));
        if (result < 0) {
            qWarning() << "Failed to write to kill socket:" << errno;
        }
    }
    _workerThread.join();
}

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

#include "common.h"
#line SOURCE_FILE("apinetwork.cpp")

#include "apinetwork.h"
#include "testshim.h"
#include <algorithm>
#include <QNetworkProxyFactory>
#include <QNetworkReply>
#include <QSslSocket>
#include <atomic>

namespace
{
    // Counter used to vary the proxy username.
    //
    // QNetworkAccessManager caches connections, and we can no longer clear the
    // cache for every attempt like we did in Qt 5.11 - since 5.12 clearing the
    // cache terminates in-flight requests, because it kills the worker thread.
    // (It has to kill the thread, because the caches now are thread-local
    // objects on that thread.)
    //
    // The proxy username is included in the cache key, so we can trick it into
    // never reusing connections by varying the proxy username, at least when
    // the proxy is active.
    //
    // Clearing the cache when we know we're connecting/disconnecting is also
    // beneficial, but this is difficult to time sufficiently well to guarantee
    // that reusing connections is safe, particularly given that some VPN
    // interface setup is done asynchronously (such as configuring the interface
    // IP with WireGuard on Windows).
    //
    // This is atomic in case it might be used from QNAM's HTTP worker thread.
    std::atomic<std::uint32_t> proxyUsernameCounter;

    // A QNetworkProxyFactory that always returns the same proxy, but with a
    // varying username to trick the QNAM connection cache.  See
    // ApiNetwork::setProxy().
    class UsernameCounterProxyFactory : public QNetworkProxyFactory
    {
    public:
        UsernameCounterProxyFactory(QNetworkProxy proxy) : _proxy{std::move(proxy)} {}

    public:
        virtual QList<QNetworkProxy> queryProxy(const QNetworkProxyQuery &) override
        {
            QNetworkProxy result{_proxy};
            std::uint32_t counter = proxyUsernameCounter++;
            result.setUser(result.user() + QString::number(counter));
            return {std::move(result)};
        }

    private:
        const QNetworkProxy _proxy;
    };
    
    // Custom QNetworkAccessManager that supports SNI hostname override
    class SniAwareNetworkAccessManager : public QNetworkAccessManager
    {
    public:
        SniAwareNetworkAccessManager(QObject *parent = nullptr) : QNetworkAccessManager(parent) {}
        
    protected:
        // Override createRequest to check for SNI hostname attribute
        virtual QNetworkReply *createRequest(Operation op, 
                                            const QNetworkRequest &request,
                                            QIODevice *outgoingData = nullptr) override
        {
            // Check if we have an SNI hostname override
            QNetworkRequest modifiedRequest(request);
            QVariant sniHostname = request.attribute(ApiNetwork::SNI_HOSTNAME_ATTRIBUTE);
            
            if (sniHostname.isValid() && sniHostname.canConvert<QString>()) {
                QString hostname = sniHostname.toString();
                
                // First, connect the SSL errors signal to handle errors appropriately
                QNetworkReply *reply = QNetworkAccessManager::createRequest(op, modifiedRequest, outgoingData);
                
                // Connect to the SSL errors signal to be able to check and potentially
                // ignore certificate errors related to hostname mismatch
                connect(reply, &QNetworkReply::sslErrors, this, 
                    [reply, hostname](const QList<QSslError> &errors) {
                        bool onlyHostnameMismatch = true;
                        for (const auto &error : errors) {
                            if (error.error() != QSslError::HostNameMismatch) {
                                onlyHostnameMismatch = false;
                                break;
                            }
                        }
                        
                        if (onlyHostnameMismatch) {
                            // Verify the certificate against our expected hostname
                            QSslCertificate cert = reply->sslConfiguration().peerCertificate();
                            bool nameMatches = false;
                            
                            // Check if hostname matches any SANs
                            QStringList altNames = cert.subjectAlternativeNames().values(QSsl::AlternativeNameEntryType::DnsEntry);
                            for (const auto &altName : altNames) {
                                if (QString::compare(altName, hostname, Qt::CaseInsensitive) == 0) {
                                    nameMatches = true;
                                    break;
                                }
                            }
                            
                            // Also check common name as fallback
                            if (!nameMatches) {
                                QString commonName = cert.subjectInfo(QSslCertificate::CommonName).join(", ");
                                if (QString::compare(commonName, hostname, Qt::CaseInsensitive) == 0) {
                                    nameMatches = true;
                                }
                            }
                            
                            if (nameMatches) {
                                qInfo() << "Verified certificate for" << hostname << "- ignoring hostname mismatch";
                                reply->ignoreSslErrors();
                            } else {
                                qWarning() << "Certificate name mismatch: Expected" << hostname
                                         << "but certificate is for" << altNames.join(", ");
                            }
                        }
                    });
                
                return reply;
            }
            
            // No SNI override, just use the normal request
            return QNetworkAccessManager::createRequest(op, modifiedRequest, outgoingData);
        }
    };
}

// Define the SNI hostname attribute
const QNetworkRequest::Attribute ApiNetwork::SNI_HOSTNAME_ATTRIBUTE = 
    static_cast<QNetworkRequest::Attribute>(1001);

ApiNetwork::ApiNetwork()
{
    // Use our custom network access manager that supports SNI hostname overrides
    _pAccessManager.reset(TestShim::create<SniAwareNetworkAccessManager>());
}

void ApiNetwork::setProxy(QNetworkProxy proxy)
{
    // If we were to set the proxy with QNetworkAccessManager::setProxy(), then
    // it will assume that the proxy can only handle one request at a time.
    // That means that after connecting, when we try to refresh all regions
    // lists (as well as PF, login, etc.), only one request will go through at
    // a time, and the others could time out before they get a chance to use the
    // proxy.
    //
    // Insead, use a proxy factory, which returns a new QNetworkProxy object for
    // every request (with the same proxy configuration every time).  This
    // allows all requests to use the proxy at the same time.
    //
    // Additionally, this proxy factory varies the username in order to trick
    // the QNAM connection cache.
    getAccessManager().setProxyFactory(new UsernameCounterProxyFactory{std::move(proxy)});
    // Clear the connection cache now.  It's possible that ongoing request might
    // actually complete in this case, but since we're starting the proxy we
    // want to abandon them anyway.
    getAccessManager().clearConnectionCache();
}

void ApiNetwork::clearProxy()
{
    getAccessManager().setProxyFactory(nullptr);
    // Clear the connection cache now.  This kills any ongoing requests, but
    // since we're shutting down the proxy, that's fine.
    getAccessManager().clearConnectionCache();
}

QNetworkAccessManager &ApiNetwork::getAccessManager() const
{
    Q_ASSERT(_pAccessManager);  // Class invariant
    return *_pAccessManager;
}

template class COMMON_EXPORT AutoSingleton<ApiNetwork>;

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

#include "apibase.h"
ApiBaseData::ApiBaseData(const std::vector<QString> &baseUris)
    : _baseUris{}, _nextStartIndex{0}
{
    _baseUris.reserve(baseUris.size());
    for(auto &uri : baseUris)
        addBaseUri(uri, {}, {});
}

ApiBaseData::ApiBaseData(const std::initializer_list<QString> &baseUris)
    : _baseUris{}, _nextStartIndex{0}
{
    _baseUris.reserve(baseUris.size());
    for(auto &uri : baseUris)
        addBaseUri(uri, {}, {});
}

ApiBaseData::ApiBaseData(const QString &uri, std::shared_ptr<PrivateCA> pCA,
                         const QString &peerVerifyName)
    : _baseUris{}, _nextStartIndex{0}
{
    addBaseUri(uri, std::move(pCA), peerVerifyName);
}

ApiBaseData::ApiBaseData(std::vector<BaseUri> baseUris)
    : _baseUris{std::move(baseUris)}, _nextStartIndex{0}
{
    // Ensure all bases end with '/'
    for(auto &base : _baseUris)
    {
        if(!base.uri.endsWith('/'))
            base.uri += '/';
    }
}

void ApiBaseData::addBaseUri(const QString &uri, std::shared_ptr<PrivateCA> pCA,
                             const QString &peerVerifyName)
{
    if(!uri.endsWith('/'))
        _baseUris.push_back({uri + '/', std::move(pCA), peerVerifyName});
    else
        _baseUris.push_back({uri, std::move(pCA), peerVerifyName});
}

BaseUri ApiBaseData::getUri(unsigned index)
{
    Q_ASSERT(index < _baseUris.size());   // Guaranteed by caller
    return _baseUris[index];
}

void ApiBaseData::attemptSucceeded(unsigned successIndex)
{
    Q_ASSERT(successIndex < _baseUris.size());  // Guaranteed by caller
    _nextStartIndex = successIndex;
}

ApiBaseSequence FixedApiBase::beginAttempt()
{
    Q_ASSERT(_pData);   // Class invariant
    return {_pData};
}

unsigned FixedApiBase::getAttemptCount(unsigned attemptsPerBase)
{
    Q_ASSERT(_pData);   // Class invariant
    return _pData->getUriCount() * attemptsPerBase;
}

std::shared_ptr<PrivateCA> FixedApiBase::createCAFromX509(const QString &x509CertData)
{
    if (x509CertData.isEmpty()) {
        return nullptr;
    }
    
    // Convert the Base64 certificate to PEM format
    QByteArray pemData = "-----BEGIN CERTIFICATE-----\n";
    
    // Add the certificate data with proper line wrapping (64 chars per line)
    QByteArray certData = x509CertData.toLatin1();
    for (int i = 0; i < certData.size(); i += 64) {
        pemData.append(certData.mid(i, 64));
        pemData.append('\n');
    }
    
    pemData.append("-----END CERTIFICATE-----\n");
    
    // Create a PrivateCA from the PEM data
    try {
        return std::make_shared<PrivateCA>(pemData);
    } catch (...) {
        qWarning() << "Failed to create PrivateCA from X509 certificate data";
        return nullptr;
    }
}

FixedApiBase::FixedApiBase(const QString &uri, const QString &peerVerifyName, const QString &x509CertData)
    : _pData{new ApiBaseData{uri, createCAFromX509(x509CertData), peerVerifyName}}
{
    // If creating the CA failed, log a warning
    if (!x509CertData.isEmpty() && !_pData->getUri(0).pCA) {
        qWarning() << "Failed to create CA from provided X509 data. Will use system certificates instead.";
    }
}

ApiBaseSequence::ApiBaseSequence(QSharedPointer<ApiBaseData> pData)
    : _pData{std::move(pData)}
{
    Q_ASSERT(_pData);   // Guaranteed by caller

    // Back up _nextBaseUri relative to the start so getNextUri() can increment
    // it normally
    unsigned startIndex = _pData->getNextStartIndex();
    _currentBaseUri = startIndex ? startIndex-1 : _pData->getUriCount()-1;
}

BaseUri ApiBaseSequence::getNextUri()
{
    Q_ASSERT(_pData);   // Class invariant
    _currentBaseUri = (_currentBaseUri + 1) % _pData->getUriCount();
    return _pData->getUri(_currentBaseUri);
}

void ApiBaseSequence::attemptSucceeded()
{
    Q_ASSERT(_pData);   // Class invariant
    _pData->attemptSucceeded(_currentBaseUri);
}

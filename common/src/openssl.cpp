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
#line SOURCE_FILE("openssl.cpp")

#include "openssl.h"
#include "builtin/path.h"

#include <QDir>
#include <QLibrary>
#include <QSslSocket>

#include <cctype>

#if defined(Q_OS_WIN)
    #if defined(_M_X64)
        static const QString libsslName = QStringLiteral("libssl-3-x64.dll");
        static const QString libcryptoName = QStringLiteral("libcrypto-3-x64.dll");
    #elif defined(_M_ARM64)
        static const QString libsslName = QStringLiteral("libssl-3-arm64.dll");
        static const QString libcryptoName = QStringLiteral("libcrypto-3-arm64.dll");
    #else
        #error Unsupported OS/arch
    #endif
#elif defined(Q_OS_MACOS)
        static const QString libsslName = QStringLiteral("libssl.3.dylib");
        static const QString libcryptoName = QStringLiteral("libcrypto.3.dylib");
#elif defined(Q_OS_LINUX)
        static const QString libsslName = QStringLiteral("libssl.so.3");
        static const QString libcryptoName = QStringLiteral("libcrypto.so.3");
#endif

// libssl

struct EVP_MD_CTX;
struct EVP_PKEY_CTX;
struct EVP_MD;
struct ENGINE;
struct BIO;
struct EVP_PKEY;
struct X509;
struct X509_STORE;
struct X509_STORE_CTX;
struct stack_st;
struct stack_st_X509;
typedef int (*pem_password_cb)(char* buf, int size, int rwflag, void* u);
typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);
typedef int (*X509_STORE_CTX_verify_cb)(int, X509_STORE_CTX *);

enum
{
    EVP_PKEY_X25519 = 1034, // NID_X25519
    X509_V_ERR_CERT_HAS_EXPIRED = 10,
    X509_V_OK = 0,
};

static void (*CRYPTO_free)(void*) = nullptr;

static void (*ERR_print_errors_cb)(int (*cb)(const char* str, size_t len, void* u), void* u) = nullptr;

static BIO* (*BIO_new_mem_buf)(const void *buf, int len) = nullptr;
static void (*BIO_free)(BIO* bp) = nullptr;

static EVP_PKEY* (*PEM_read_bio_PUBKEY)(BIO* bp, EVP_PKEY** x, pem_password_cb* cb, void* u);
static X509* (*PEM_read_bio_X509)(BIO*, X509**, pem_password_cb*, void*) = nullptr;
static X509* (*PEM_read_bio_X509_AUX)(BIO*, X509**, pem_password_cb*, void*) = nullptr;

static EVP_MD_CTX* (*EVP_MD_CTX_new)() = nullptr;
static void (*EVP_MD_CTX_free)(EVP_MD_CTX* ctx) = nullptr;

static const EVP_MD* (*EVP_sha256)() = nullptr;

static void (*EVP_PKEY_free)(EVP_PKEY* pkey) = nullptr;

static int (*EVP_DigestVerifyInit)(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx, const EVP_MD* type, ENGINE* e, EVP_PKEY* pkey) = nullptr;
static int (*EVP_DigestUpdate)(EVP_MD_CTX* ctx, const void* d, size_t cnt) = nullptr;
static int (*EVP_DigestVerifyFinal)(EVP_MD_CTX* ctx, const unsigned char* sig, size_t siglen) = nullptr;

static void (*X509_free)(X509*) = nullptr;
static int (*X509_check_host)(X509*, const char *, size_t, unsigned int, char**) = nullptr;

static X509_STORE* (*X509_STORE_new)(void) = nullptr;
static void (*X509_STORE_free)(X509_STORE*) = nullptr;
static int (*X509_STORE_add_cert)(X509_STORE*, X509*) = nullptr;

static X509_STORE_CTX* (*X509_STORE_CTX_new)(void) = nullptr;
static void (*X509_STORE_CTX_free)(X509_STORE_CTX *) = nullptr;
static int (*X509_STORE_CTX_init)(X509_STORE_CTX*, X509_STORE*, X509*, stack_st_X509*) = nullptr;
static int (*X509_STORE_CTX_get_error)(X509_STORE_CTX*) = nullptr;
static int (*X509_STORE_CTX_get_error_depth)(X509_STORE_CTX*) = nullptr;

static void (*X509_STORE_CTX_set_verify_cb)(X509_STORE_CTX *ctx,
                                   X509_STORE_CTX_verify_cb verify_cb) = nullptr;

static int (*X509_verify_cert)(X509_STORE_CTX*) = nullptr;
static const char * (*X509_verify_cert_error_string)(long) = nullptr;

static X509* (*d2i_X509)(X509**, unsigned char **, long) = nullptr;

static EVP_PKEY_CTX* (*EVP_PKEY_CTX_new_id)(int, ENGINE*) = nullptr;
static void (*EVP_PKEY_CTX_free)(EVP_PKEY_CTX*) = nullptr;

static int (*EVP_PKEY_keygen_init)(EVP_PKEY_CTX *) = nullptr;
static int (*EVP_PKEY_keygen)(EVP_PKEY_CTX*, EVP_PKEY**) = nullptr;
static int (*EVP_PKEY_get_raw_private_key)(const EVP_PKEY*, unsigned char *, size_t *) = nullptr;
static int (*EVP_PKEY_get_raw_public_key)(const EVP_PKEY*, unsigned char *, size_t *) = nullptr;

static stack_st* (*OPENSSL_sk_new_reserve)(OPENSSL_sk_compfunc, int);
static int (*OPENSSL_sk_push)(stack_st*, const void*) = nullptr;
static void (*OPENSSL_sk_free)(stack_st*) = nullptr;

static unsigned long (*OpenSSL_version_num)() = nullptr;
static const char *(*OpenSSL_version)(int) = nullptr;

static int permitExpiredCallback(int preverify, X509_STORE_CTX* ctx)
{
    int error = X509_STORE_CTX_get_error(ctx);
    if (error == X509_V_OK || error == X509_V_ERR_CERT_HAS_EXPIRED)
        return 1;

    return preverify;
}

static bool checkOpenSSL()
{
    static bool attempted = false, successful = false;

    if (successful)
        return true;
    if (attempted)
        return false;

    attempted = true;

    const auto &libcryptoPath = Path::LibraryDir / libcryptoName;
    // The library is never unloaded (note that the QLibrary dtor does not
    // unload the library)
    QLibrary libcrypto{libcryptoPath};

    // We load libcrypto from our App Library path.
    // We specify the full path to the library to prevent it falling back to system libraries if it fails.
    // (Path::LibraryDir - /opt/piavpn/lib/ on Linux)
    // The LibraryDir path depends on QCoreApplication::applicationDirPath(),
    // which is where the pia-daemon binary is located.
    //
    // Qt (via the QtNetwork library) also attempts to load libcrypto (and libssl).
    // It starts its search in our App Library path too (as we set an rpath) but upon failure,
    // it WILL search and use system libraries if it finds them.
    // Check the section "Where does the system look for dynamic libraries?"
    // in this document: docs/Dynamic libraries.md
    // to know the exact order in which these libs will be searched.
    //
    // We therefore need to be careful that both PIA and Qt expect the same libraries with the same names
    // to prevent them loading incompatible versions of libcrypto.
    //
    //
    // On Linux use this command:
    // `sudo pldd $(pgrep pia-daemon) | grep crypto`
    // to list both:
    // - the libraries that have been dynamically loaded using dlopen(3)
    // - the dynamic shared objects (DSOs) that are linked into the process
    // $ sudo pldd $(pgrep pia-daemon) | grep crypto
    //
    // Check also Openssl historical notes in this document: docs/Openssl.md
    if(!libcrypto.load())
    {
        qWarning() << "Unable to load libcrypto from" << libcryptoPath
            << "-" << libcrypto.errorString();
        return false;
    }

    qInfo() << "Loaded libcrypto from" << libcrypto.fileName();

#define TRY_RESOLVE_OPENSSL_FUNCTION(name) \
    (name = reinterpret_cast<decltype(name)>(libcrypto.resolve(#name)))
#define RESOLVE_OPENSSL_FUNCTION(name) \
    if (!TRY_RESOLVE_OPENSSL_FUNCTION(name)) { qError() << "Unable to resolve symbol" << #name; return false; } else ((void)0)

    RESOLVE_OPENSSL_FUNCTION(CRYPTO_free);

    RESOLVE_OPENSSL_FUNCTION(ERR_print_errors_cb);

    RESOLVE_OPENSSL_FUNCTION(BIO_new_mem_buf);
    RESOLVE_OPENSSL_FUNCTION(BIO_free);

    RESOLVE_OPENSSL_FUNCTION(PEM_read_bio_PUBKEY);
    RESOLVE_OPENSSL_FUNCTION(PEM_read_bio_X509);
    RESOLVE_OPENSSL_FUNCTION(PEM_read_bio_X509_AUX);

    RESOLVE_OPENSSL_FUNCTION(EVP_MD_CTX_new);
    RESOLVE_OPENSSL_FUNCTION(EVP_MD_CTX_free);

    RESOLVE_OPENSSL_FUNCTION(EVP_sha256);

    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_free);

    RESOLVE_OPENSSL_FUNCTION(EVP_DigestVerifyInit);
    RESOLVE_OPENSSL_FUNCTION(EVP_DigestUpdate);
    RESOLVE_OPENSSL_FUNCTION(EVP_DigestVerifyFinal);

    RESOLVE_OPENSSL_FUNCTION(X509_free);
    RESOLVE_OPENSSL_FUNCTION(X509_check_host);

    RESOLVE_OPENSSL_FUNCTION(X509_STORE_new);
    RESOLVE_OPENSSL_FUNCTION(X509_STORE_free);
    RESOLVE_OPENSSL_FUNCTION(X509_STORE_add_cert);

    RESOLVE_OPENSSL_FUNCTION(X509_STORE_CTX_new);
    RESOLVE_OPENSSL_FUNCTION(X509_STORE_CTX_free);
    RESOLVE_OPENSSL_FUNCTION(X509_STORE_CTX_init);
    RESOLVE_OPENSSL_FUNCTION(X509_STORE_CTX_get_error);
    RESOLVE_OPENSSL_FUNCTION(X509_STORE_CTX_get_error_depth);
    RESOLVE_OPENSSL_FUNCTION(X509_STORE_CTX_set_verify_cb);

    RESOLVE_OPENSSL_FUNCTION(X509_verify_cert);
    RESOLVE_OPENSSL_FUNCTION(X509_verify_cert_error_string);

    RESOLVE_OPENSSL_FUNCTION(d2i_X509);

    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_CTX_new_id);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_CTX_free);

    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_keygen_init);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_keygen);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_get_raw_private_key);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_get_raw_public_key);

    RESOLVE_OPENSSL_FUNCTION(OPENSSL_sk_new_reserve);
    RESOLVE_OPENSSL_FUNCTION(OPENSSL_sk_free);
    RESOLVE_OPENSSL_FUNCTION(OPENSSL_sk_push);

    RESOLVE_OPENSSL_FUNCTION(OpenSSL_version_num);
    RESOLVE_OPENSSL_FUNCTION(OpenSSL_version);

#undef RESOLVE_OPENSSL_FUNCTION
#undef TRY_RESOLVE_OPENSSL_FUNCTION

    successful = true;

    unsigned long libVersion{OpenSSL_version_num()};
    // The OpenSSL version number has the form:
    // 0xMNNPPPS
    //   || |  ^status (f == release)
    //   || ^patch
    //   ||
    //   |^ minor
    //   ^ major
    auto patchChar = [](unsigned idx) -> char
    {
        if(idx == 0)
            return ' '; // No letter
        if(idx <= 26)
            return ('a' - 1) + idx;
        return '?';
    };
    // Trace the numeric version number from OpenSSL.  This should match the
    // text version returned by OpenSSL later.
    qInfo().nospace() << "Loaded OpenSSL " << (libVersion >> 28) << '.'
        << ((libVersion >> 20) & 0xFF) << '.'
        << ((libVersion >> 4) & 0xFFF)
        << patchChar(libVersion & 0xF);
    qInfo().nospace() << "Check that the loaded OpenSSL version matches the one below";

    if((libVersion >> 28) != 0x3)
        qWarning() << "Using an unsupported OpenSSL version!";

    // Trace some build info from OpenSSL.  Print everything available, ranging
    // from OPENSSL_VERSION (0) to OPENSSL_ENGINES_DIR (5)
    for(int i=0; i<6; ++i)
        qInfo() << "  " << QLatin1String(OpenSSL_version(i));

    return true;
}

static EVP_PKEY* createPublicKeyFromPem(const QByteArray& pem)
{
    if (pem.isEmpty())
        return nullptr;
    BIO *bio = BIO_new_mem_buf(const_cast<char*>(pem.data()), pem.size());
    EVP_PKEY* result = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return result;
}

bool verifySignature(const QByteArray& publicKeyPem, const QByteArray& signature, const QByteArray& data)
{
    // For the time being, treat OpenSSL errors (e.g. unable to find the
    // library) as though the signature validated successfully.
    if (!checkOpenSSL()) return true;

    auto md = EVP_sha256();
    if (!md) return false;

    EVP_PKEY* pkey = createPublicKeyFromPem(publicKeyPem);
    if (!pkey) return false;
    AT_SCOPE_EXIT(EVP_PKEY_free(pkey));

    auto ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    AT_SCOPE_EXIT(EVP_MD_CTX_free(ctx));

    if (1 == EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey) &&
        1 == EVP_DigestUpdate(ctx, data.data(), static_cast<size_t>(data.size())) &&
        1 == EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(signature.data()), static_cast<size_t>(signature.size())))
        return true;

    ERR_print_errors_cb([](const char* str, size_t len, void*) {
        qWarning() << QLatin1String(str, static_cast<int>(len));
        return 0;
    }, nullptr);

    return false;
}

class OpenSSLDeleter
{
private:
    void del(EVP_PKEY_CTX *p){EVP_PKEY_CTX_free(p);}
    void del(EVP_PKEY *p){EVP_PKEY_free(p);}
    void del(X509_STORE *p){X509_STORE_free(p);}
    void del(X509_STORE_CTX *p){X509_STORE_CTX_free(p);}
    void del(X509 *p){X509_free(p);}
    void del(BIO *p){BIO_free(p);}
    void del(stack_st *p){OPENSSL_sk_free(p);}
    void del(char *p){CRYPTO_free(p);}

public:
    // Don't try to free nullptrs - the OpenSSL functions might not have been
    // loaded in that case.
    template<class T>
    void operator()(T *p){if(p) del(p);}
};

template<class T>
using OpenSSLPtr = std::unique_ptr<T, OpenSSLDeleter>;

struct PrivateCA::data
{
    OpenSSLPtr<X509_STORE> pCertStore;
};

OpenSSLPtr<X509> convertCert(const QSslCertificate &cert)
{
    auto der = cert.toDer();
    auto pDataPos = reinterpret_cast<unsigned char*>(der.data());
    return OpenSSLPtr<X509>{d2i_X509(nullptr, &pDataPos, der.size())};
}

PrivateCA::PrivateCA(const QByteArray &caCertPem)
    : _pData{new data{}}
{
    if(!checkOpenSSL())
        return;

    // Create the cert store.  Put it in _pData only once we've successfully
    // loaded the certificate.
    OpenSSLPtr<X509_STORE> pCertStore{X509_STORE_new()};
    if(!pCertStore)
    {
        qWarning() << "Unable to create cert store";
        return;
    }

    // Read the specified CA certificate
    OpenSSLPtr<BIO> pCaFile{BIO_new_mem_buf(caCertPem.data(), caCertPem.size())};
    if(!pCaFile)
    {
        qWarning() << "Can't open CA data";
        return;
    }

    OpenSSLPtr<X509> pCaCert{PEM_read_bio_X509_AUX(pCaFile.get(), nullptr, nullptr, nullptr)};
    if(!pCaCert)
    {
        qWarning() << "Can't read CA cert data";
        return;
    }

    if(!X509_STORE_add_cert(pCertStore.get(), pCaCert.get()))
    {
        qWarning() << "Can't add CA cert to cert store";
        return;
    }

    // Successfully initialized the cert store containing the specified root
    // certificate
    _pData->pCertStore = std::move(pCertStore);
}

PrivateCA::~PrivateCA()
{
    // Out of line to destroy _pData; PrivateCA::data is opaque
}

bool PrivateCA::verifyHttpsCertificate(const QList<QSslCertificate> &certificateChain,
                                       const QString &peerName,
                                       bool allowExpired)
{
    Q_ASSERT(_pData);   // Class invariant
    // If we were not able to load the cert store, fail.  This includes failure
    // to load OpenSSL itself, and also includes failures to read the cert, etc.
    if(!_pData->pCertStore)
    {
        qWarning() << "Could not load OpenSSL";
        return false;
    }

    // Convert the certificates
    std::vector<OpenSSLPtr<X509>> certObjs;
    certObjs.reserve(certificateChain.size());
    for(const auto &cert : certificateChain)
    {
        auto pCertObj = convertCert(cert);
        if(!pCertObj)
        {
            qWarning() << "Can't convert certificate" << certObjs.size()
                << "for peer" << peerName;
            return false;
        }
        certObjs.push_back(std::move(pCertObj));
    }

    if(certObjs.empty())
    {
        qWarning() << "No certificates in chain for" << peerName;
        return false;
    }

    // The first cert is the leaf cert.  The remaining certs are intermediate
    // certs, put them in an OpenSSL stack.  (Note the stack does not own the
    // objects, they're still owned by certObjs.)
    OpenSSLPtr<stack_st> pIntermediateCerts{OPENSSL_sk_new_reserve(nullptr, certObjs.size()-1)};
    if(!pIntermediateCerts)
    {
        qWarning() << "Can't allocate stack of intermediate certs for" << peerName;
        return false;
    }

    auto itNextCert = certObjs.begin();
    ++itNextCert;   // Skip leaf cert
    while(itNextCert != certObjs.end())
    {
        OPENSSL_sk_push(pIntermediateCerts.get(), itNextCert->get());
        ++itNextCert;
    }

    // Create a validation context using the certificates specified
    OpenSSLPtr<X509_STORE_CTX> pContext{X509_STORE_CTX_new()};
    if(!pContext)
    {
        qWarning() << "Can't allocate validation context for" << peerName;
        return false;
    }

    if(!X509_STORE_CTX_init(pContext.get(), _pData->pCertStore.get(),
                            certObjs.front().get(),
                            reinterpret_cast<stack_st_X509*>(pIntermediateCerts.get())))
    {
        qWarning() << "Can't initialize validation context for" << peerName;
        return false;
    }

    if (allowExpired)
        X509_STORE_CTX_set_verify_cb(pContext.get(), permitExpiredCallback);

    int verifyResult = X509_verify_cert(pContext.get());
    // OpenSSL returns 1 for success, 0 for failure, or "in exceptional
    // circumstances it can also return a negative code" - check for 1 exactly
    if(verifyResult != 1)
    {
        qWarning() << "Cert validation failed with result" << verifyResult
            << "for" << peerName;
        int errorCode = X509_STORE_CTX_get_error(pContext.get());
        qWarning() << "Validation error" << errorCode << "at depth"
            << X509_STORE_CTX_get_error_depth(pContext.get()) << "-"
            << QString::fromUtf8(X509_verify_cert_error_string(errorCode));
        return false;
    }

    // Check the host name
    const auto &peerUtf8 = peerName.toUtf8();
    char *pMatchedNameRaw{nullptr};
    int checkHostResult = X509_check_host(certObjs.front().get(),
                                          peerUtf8.data(), peerUtf8.size(), 0,
                                          &pMatchedNameRaw);
    // Own the matched name
    OpenSSLPtr<char> pMatchedName{pMatchedNameRaw};
    if(checkHostResult != 1)
    {
        qWarning() << "Cert hostname validation failed with result"
            << checkHostResult << "for" << peerName;
        return false;
    }

    qInfo() << "Accepted matching name" << QString::fromUtf8(pMatchedName.get())
        << "for peer" << peerName;
    return true;
}

bool genCurve25519KeyPair(unsigned char *pPubkey, unsigned char *pPrivkey)
{
    if(!checkOpenSSL())
        return false;

    OpenSSLPtr<EVP_PKEY_CTX> pPkeyCtx{EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr)};
    if(!pPkeyCtx)
    {
        qWarning() << "Unable to create curve25519 context";
        return false;
    }

    int result = EVP_PKEY_keygen_init(pPkeyCtx.get());
    if(result != 1)
    {
        qWarning() << "Unable to initialize curve25519 keygen context -" << result;
        return false;
    }

    EVP_PKEY *pPkeyRaw{nullptr};
    result = EVP_PKEY_keygen(pPkeyCtx.get(), &pPkeyRaw);
    OpenSSLPtr<EVP_PKEY> pPkey{pPkeyRaw};
    if(result != 1 || !pPkey)
    {
        qWarning() << "Unable to generate key -" << result;
        return false;
    }

    size_t keylen{0};
    result = EVP_PKEY_get_raw_private_key(pPkey.get(), nullptr, &keylen);
    if(result != 1 || keylen != Curve25519KeySize)
    {
        qWarning() << "Unable to get private key length -" << result << "-" << keylen;
        return false;
    }
    result = EVP_PKEY_get_raw_private_key(pPkey.get(), pPrivkey, &keylen);
    if(result != 1 || keylen != Curve25519KeySize)
    {
        qWarning() << "Unable to get private key -" << result << "-" << keylen;
        return false;
    }

    result = EVP_PKEY_get_raw_public_key(pPkey.get(), nullptr, &keylen);
    if(result != 1 || keylen != Curve25519KeySize)
    {
        qWarning() << "Unable to get public key length -" << result << "-" << keylen;
        return false;
    }
    result = EVP_PKEY_get_raw_public_key(pPkey.get(), pPubkey, &keylen);
    if(result != 1 || keylen != Curve25519KeySize)
    {
        qWarning() << "Unable to get public key -" << result << "-" << keylen;
        return false;
    }

    return true;
}

std::shared_ptr<PrivateCA> createPrivateCAFromX509(const QString &x509CertData)
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
    
    // Log detailed information for debugging
    qInfo() << "Creating PrivateCA from X509 certificate data";
    
    // Create a PrivateCA from the PEM data
    try {
        // Convert PEM to QSslCertificate for proper certificate handling
        QSslCertificate cert(pemData);
        if (cert.isNull()) {
            qWarning() << "Failed to parse X509 certificate from PEM data";
            throw std::runtime_error("Invalid X509 certificate");
        }
        
        // Verify that the certificate converted correctly
        if (cert.serialNumber().isEmpty()) {
            qWarning() << "Certificate parsed but appears invalid";
            throw std::runtime_error("Invalid certificate data");
        }
        
        auto pCA = std::make_shared<PrivateCA>(pemData);
        // Store the certificate object directly for proper comparison
        pCA->setStoredCertificate(cert);
        
        // Log certificate info for debugging - avoid logging the entire certificate directly 
        qInfo() << "Parsed X509 certificate: CN=" << cert.subjectInfo(QSslCertificate::CommonName).join(", ") 
                << " Serial=" << cert.serialNumber()
                << " Expires=" << cert.expiryDate().toString();
        return pCA;
    } catch (const std::exception &e) {
        qWarning() << "Failed to create PrivateCA from X509 certificate data:" << e.what();
        return nullptr;
    } catch (...) {
        qWarning() << "Failed to create PrivateCA from X509 certificate data: unknown error";
        return nullptr;
    }
}

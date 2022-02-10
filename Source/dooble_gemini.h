//what copyright header should be here..?

#ifndef dooble_gemini_h
#define dooble_gemini_h

#include <QAbstractSocket>
#include <QBuffer>
#include <QMetaEnum>
#include <QPointer>
#include <QRegularExpression>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QUrl>
#include <QWebEngineUrlRequestJob>
#include <QWebEngineUrlSchemeHandler>

#include "dooble_web_engine_view.h"


class StatusCode
{
  Q_GADGET
public:
  enum StatusCodeEnum {
    // Equivalent to undefined or invalid.
    Unknown                       = -1,
    /*
     * Server has requested the user's input.
     * Any prompt for the user is supplied in the META field.
     */
    Input                         = 10,
    /*
     * Server has requested the user's input.
     * Server has indicated that the input may be sensitive in nature (eg. credentials, PII)
     * Any prompt for the user is supplied in the META field.
     */
    InputSensitive                = 11,
    /*
     * Server has successfully fulfilled the request.
     * Server will disconnect after delivering the full BODY contents.
     * Server will indicate the nature of the BODY in the META field.
     */
    Success                       = 20,
    /*
     * Server has indicated that the requested location has moved.
     * The new location is indicated in the META field.
     */
    RedirectTemporary             = 30,
    /*
     * Server has indicated that the requested location has moved,
     * to a permanent end, and the client may wish to keep this in a temporary cache.
     * The new location is indicated in the META field.
     */
    RedirectPermanent             = 31,
    /*
     * Server was unable to fulfil the request.
     * Any reason for this failure is supplied in the META field.
     * The user (or client) may retry the request.
     */
    FailureTemporary              = 40,
    /*
     * Server was unable to fulfil the request, due to a backend failure
     * of some kind. More information about this failure may be indicated
     * in the META field.
     * The user (or client) may retry the request.
     */
    FailureServerUnavailable      = 41,
    /*
     * Server was unable to fulfil the request.
     * Server indicated that it executed CGI during fulfilment of this request,
     * but the CGI execution failed for a reason that might be indicated in
     * the META field.
     * The user (or client) may retry the request.
     */
    // disconnect and display temporary error page with META
    FailureCgiError               = 42,
    /*
     * A proxy server between the client and the actual server was unable
     * to fulfil this request. More information about the failure may
     * be indicated in the META field.
     * The user (or client) may retry the request.
     */
    FailureProxyError             = 43,
    /*
     * Server was unable to fulfil the request due to rate-limiting, and
     * has requested that the client make fewer requests.
     * More information about the rate-limit may be indicated in the
     * META field.
     * The user (or client) may retry the request.
     */
    FailureSlowDown               = 44,
    /*
     * Server was unable to fulfil this request, and the nature of this failure
     * is such that retrying the request is unlikely to succeed.
     * More information about this failure may be indicated in the META field.
     * The user may retry the request, but the client should not do so automatically.
     */
    FailurePermanent              = 50,
    /*
     * Server was unable to fulfil the request because the requested location
     * is not known to the server.
     * More information may be indicated in the META field.
     * The user may retry the request if they are particularly insistent.
     */
    NotFound                      = 51,
    /*
     * Server was unable to fulfil the request because the requested location
     * refers to a document that is no longer available.
     * More information may be indicated in the META field.
     * The user may retry the request if they are particularly insistent.
     */
    Gone                          = 52,
    /*
     * A proxy server between the client and the actual server refused to
     * service this request.
     * More information about this refusal may be indicated in the META field.
     * The user may retry the request at their own peril.
     */
    FailureProxyRequestRefused    = 53,
    /*
     * Server was unable to fulfil the request because the request was malformed,
     * non-compliant with specifications, the input was unexpected, of a format
     * not requested or desired by the server, or something about the request
     * was simply undesired by the server.
     * More information about this failure may be indicated in the META field.
     * The user may retry the request if they are very sure it is not actually bad.
     */
    FailureBadRequest             = 59,
    /*
     * Server has requested authentication of the client by way of certificates.
     * The server's certificate expectations and requirements may be indicated
     * in the META field, aiding the automatic or manual selection of a
     * certificate.
     * The client may prompt the user to authenticate with a certificate, or
     * automatically retry the request with a pre-set certificate that the user
     * has indicated may be sent automatically when requested.
     */
    ClientCertificateRequired     = 60,
    /*
     * Server indicated that the certificate recieved from the client was
     * not sufficient to authenticate the client; the certificate may be
     * issued by a different certificate authority than the server expected,
     * or the certificate may not be known to the server,
     * More information as to why the certificate was not accepted may be
     * included in the META field.
     * The client may prompt the user with the failure, requesting a different
     * certificate be selected, or may automatically retry the request and
     * supply the next certificate the user has indicated may be automatically
     * sent when requested.
     */
    ClientCertificateNotAuthorised= 61,
    /*
     * Server has indicated that the certificate received from the client was
     * not valid; the certificate may be expired, or may not yet be valid, or
     * the certificate may have failed some other validation process, such as
     * having been revoked. More information as to why the certificate was
     * not accepted may be included in the META field.
     * The client may prompt the user with the failure, requesting a different
     * certificate be selected, or may automatically retry the request and
     * supply the next certificate the user has indicated may be automatically
     * sent when requested.
     */
    ClientCertificateNotValid     = 62,
  };
  Q_ENUM(StatusCodeEnum);
};

class dooble_gemini: public QWebEngineUrlSchemeHandler
{
  Q_OBJECT

public:
  dooble_gemini(QObject *parent);

private:
  QPointer<QWebEngineUrlRequestJob> m_request;
  void requestStarted(QWebEngineUrlRequestJob *request);

private slots:
  void slot_error(QWebEngineUrlRequestJob::Error error);
  void slot_finished(const QByteArray &bytes,
                     QString content_type,
                     StatusCode::StatusCodeEnum result,
                     QString charset,
                     QString lang,
                     QString meta);
};

class dooble_gemini_implementation: public QSslSocket
{
  Q_OBJECT

public:
  dooble_gemini_implementation(const QUrl &url,
                               dooble_web_engine_view *web_engine_view,
                               QObject *parent);
  ~dooble_gemini_implementation();
  static QByteArray s_eol;

private:
  QByteArray m_content;
  QByteArray m_html;
  QPointer<dooble_web_engine_view> m_web_engine_view;
  QString m_output;
  QString m_search;
  QTimer m_write_timer;
  QUrl m_url;
  bool m_loaded;
  bool m_content_type_supported;
  bool m_is_image;
  char m_item_type;
  int m_seven_count;
  bool m_inside_pre;
  bool m_inside_list;
  bool m_inside_quote;
  QByteArray m_header;
  StatusCode::StatusCodeEnum m_status_code;
  QString m_meta;
  QString m_charset;
  QString m_content_type;
  QString m_lang;
  bool parse_header(const QByteArray &bytes);
  QByteArray plain_to_html(const QByteArray &bytes);

private slots:
  // normal slots
  void slot_encrypted(void);
  void slot_ready_read(void);
  void slot_disconnected(void);
  void slot_write_timeout(void);
  // error handling
  void slot_handshakeerror(const QSslError &err);
  void slot_peerverifyerror(QSslError err);
  void slot_sslerrors(const QList<QSslError> &errs);
  // debugging
  void slot_connected(void);
  void slot_sockerr(QAbstractSocket::SocketError);
  void slot_statechange(QAbstractSocket::SocketState state);

signals:
  void error(QWebEngineUrlRequestJob::Error error);
  void finished(const QByteArray &bytes,
                QString content_type,
                StatusCode::StatusCodeEnum result,
                QString charset,
                QString lang,
                QString meta);
};

#endif

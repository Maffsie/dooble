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
#include <QWebEngineProfile>
#include <QWebEngineSettings>
#include <QWebEngineUrlRequestJob>
#include <QWebEngineUrlSchemeHandler>

#include "dooble_web_engine_view.h"

namespace GeminiProtocol
{
    Q_NAMESPACE
    class StatusCode
    {
        Q_GADGET
    public:
        enum StatusCodeEnum {
            Unknown                       = -1,
            Input                         = 10,
            InputSensitive                = 11,
            Success                       = 20,
            RedirectTemporary             = 30,
            RedirectPermanent             = 31,
            FailureTemporary              = 40,
            FailureServerUnavailable      = 41,
            FailureCgiError               = 42,
            FailureProxyError             = 43,
            FailureSlowDown               = 44,
            FailurePermanent              = 50,
            NotFound                      = 51,
            Gone                          = 52,
            FailureProxyRequestRefused    = 53,
            FailureBadRequest             = 59,
            ClientCertificateRequired     = 60,
            ClientCertificateNotAuthorised= 61,
            ClientCertificateNotValid     = 62,
        };
        Q_ENUM(StatusCodeEnum);
    };
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
                     GeminiProtocol::StatusCode::StatusCodeEnum result,
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
  GeminiProtocol::StatusCode::StatusCodeEnum m_status_code;
  QString m_meta;
  QString m_charset;
  QString m_content_type;
  QString m_lang;
  bool parse_header(const QByteArray &bytes);
  QByteArray plain_to_html(const QByteArray &bytes);

 private slots:
  void slot_connected(void);
  void slot_encrypted(void);
  void slot_disconnected(void);
  void slot_ready_read(void);
  void slot_write_timeout(void);
  void slot_statechange(QAbstractSocket::SocketState state);
  void slot_sockerr(QAbstractSocket::SocketError);
  void slot_peerverifyerror(QSslError err);
  void slot_sslerrors(const QList<QSslError> &errs);
  void slot_handshakeerror(const QSslError &err);

 signals:
  void error(QWebEngineUrlRequestJob::Error error);
  void finished(const QByteArray &bytes,
                QString content_type,
                GeminiProtocol::StatusCode::StatusCodeEnum result,
                QString charset,
                QString lang,
                QString meta);
};

#endif

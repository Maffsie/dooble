//what copyright header should be here..?

#ifndef dooble_gemini_h
#define dooble_gemini_h

#include <QBuffer>
#include <QPointer>
#include <QTcpSocket>
#include <QUrl>
#include <QWebEngineUrlRequestJob>
#include <QWebEngineUrlSchemeHandler>

#include "dooble_web_engine_view.h"

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
		     bool content_type_supported,
		     bool is_image);
};

class dooble_gemini_implementation: public QTcpSocket
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
  bool m_content_type_supported;
  bool m_is_image;
  char m_item_type;
  int m_seven_count;
  static QByteArray plain_to_html(const QByteArray &bytes);

 private slots:
  void slot_connected(void);
  void slot_disconnected(void);
  void slot_ready_read(void);
  void slot_write_timeout(void);

 signals:
  void error(QWebEngineUrlRequestJob::Error error);
    void finished(const QByteArray &bytes,
                  bool content_type_supported,
                  bool is_image);
};

#endif

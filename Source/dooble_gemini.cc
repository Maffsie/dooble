//what copyright header should be here..?

//REFERENCES
// [1]: https://gemini.circumlunar.space/docs/specification.gmi (fetched 2022-02-08)

#include <cctype>

#include "dooble_gemini.h"
#include "dooble_web_engine_view.h"

QByteArray dooble_gemini_implementation::s_eol = "\r\n";

dooble_gemini::dooble_gemini(QObject *parent):
  QWebEngineUrlSchemeHandler(parent)
{
}

void dooble_gemini::requestStarted(QWebEngineUrlRequestJob *request)
{
  if(m_request == request || !request)
    return;

  m_request = request;

  auto gemini_implementation = new dooble_gemini_implementation
    (m_request->requestUrl(),
     qobject_cast<dooble_web_engine_view *> (parent()),
     m_request);

  connect(gemini_implementation,
      SIGNAL(error(QWebEngineUrlRequestJob::Error)),
	  this,
	  SLOT(slot_error(QWebEngineUrlRequestJob::Error)));
  connect(gemini_implementation,
      &dooble_gemini_implementation::finished,
	  this,
      &dooble_gemini::slot_finished);
}

void dooble_gemini::slot_error(QWebEngineUrlRequestJob::Error error)
{
  if(m_request)
    m_request->fail(error);
}

void dooble_gemini::slot_finished(const QByteArray &bytes,
                                  QString content_type,
                                  GeminiProtocol::StatusCode::StatusCodeEnum result,
                                  QString charset,
                                  QString lang,
                                  QString meta)
{
  if(m_request) {
    if(bytes.isEmpty())
      m_request->fail(QWebEngineUrlRequestJob::RequestFailed);
    else if(result == GeminiProtocol::StatusCode::RedirectPermanent || result == GeminiProtocol::StatusCode::RedirectTemporary)
        m_request->redirect(meta);
    else {
      //The buffer object should be deleted when m_request is.
      auto buffer = new QBuffer(m_request);
      buffer->setData(bytes);
      m_request->setProperty("Content-Encoding", charset);
      m_request->setProperty("Language", lang);
      if(content_type == "text/gemini")
          content_type = "text/html";
      m_request->reply(content_type.toUtf8(), buffer);
    }
  }
}

dooble_gemini_implementation::dooble_gemini_implementation
(const QUrl &url,
 dooble_web_engine_view *web_engine_view,
 QObject *parent): QSslSocket(parent)
{
  qDebug() << "Connect begin";
  m_write_timer.setSingleShot(true);

  qDebug() << "Registering connections";
  qDebug() << connect(this, &QAbstractSocket::stateChanged,
                      this, &dooble_gemini_implementation::slot_statechange)
           << "QAbstractSocket::StateChange";
  qDebug() << connect(this, &QSslSocket::connected,
                      this, &dooble_gemini_implementation::slot_connected)
           << "QSslSocket::Connected";
  qDebug() << connect(this, &QSslSocket::encrypted,
                      this, &dooble_gemini_implementation::slot_encrypted)
           << "QSslSocket::Encrypted";
  qDebug() << connect(this, &QSslSocket::readyRead,
                      this, &dooble_gemini_implementation::slot_ready_read)
           << "QSslSocket::ReadyRead";
  qDebug() << connect(this, &QSslSocket::disconnected,
                      this, &dooble_gemini_implementation::slot_disconnected)
           << "QSslSocket::Disconnected";
  qDebug() << connect(this, &QSslSocket::sslErrors,
                      this, &dooble_gemini_implementation::slot_sslerrors)
           << "QSslSocket::SslErrors";
  qDebug() << connect(this, &QSslSocket::peerVerifyError,
                      this, &dooble_gemini_implementation::slot_peerverifyerror)
           << "QSslSocket::PeerVerifyError";
  qDebug() << connect(&m_write_timer, &QTimer::timeout,
                      this, &dooble_gemini_implementation::slot_write_timeout)
           << "QTimer::Timeout";
  qDebug() << connect(this, &QAbstractSocket::errorOccurred,
                      this, &dooble_gemini_implementation::slot_sockerr)
           << "QAbstractSocket::ErrorOccurred";
  qDebug() << connect(this, &QSslSocket::handshakeInterruptedOnError,
                      this, &dooble_gemini_implementation::slot_handshakeerror)
           << "QSslSocket::HandshakeInterruptedOnError";

  qDebug() << "Connections registered";

  m_loaded = false;
  m_meta = "";
  m_status_code = GeminiProtocol::StatusCode::Unknown;
  m_content_type = "";
  m_lang = "";
  m_content_type_supported = true;
  m_web_engine_view = web_engine_view;
  m_is_image = false;
  m_item_type = 0;
  m_seven_count = 0;
  m_url = url;
  m_inside_pre = false;
  m_inside_list = false;
  m_inside_quote = false;

  if(m_url.port() == -1)
    m_url.setPort(1965);

  auto qsc = sslConfiguration();
  qsc.setProtocol(QSsl::TlsV1_2OrLater);
  //qsc.setCaCertificates(QList<QSslCertificate> {});
  qsc.setCaCertificates(QSslConfiguration::systemCaCertificates());
  setSslConfiguration(qsc);

  connectToHostEncrypted(m_url.host(), static_cast<quint16> (m_url.port()));
}

dooble_gemini_implementation::~dooble_gemini_implementation()
{
}

bool dooble_gemini_implementation::parse_header(const QByteArray &bytes)
{
    //ref1 section 3.1: Gemini responses - Response headers
    QRegularExpression hReSimple("^([0-9]{2})( (.*))?\r\n$");
    auto hMatches = hReSimple.match(bytes);
    //3.1 - server must not send a STATUS that is not two digits
    //3.1 - server must not send a META longer than 1024 bytes
    if(!hMatches.isValid() || (
            hMatches.lastCapturedIndex() == 3 &&
            hMatches.captured(3).length() > 1024)
    )
        return false;

    m_status_code = GeminiProtocol::StatusCode::StatusCodeEnum(hMatches.captured(1).toInt());
    if(hMatches.lastCapturedIndex() == 3)
        m_meta = hMatches.captured(3);

    switch (m_status_code) {
    case GeminiProtocol::StatusCode::Input:
    case GeminiProtocol::StatusCode::InputSensitive:
        //3.2.1 - [1x] INPUT
        // disconnect, prompt the user with the message contained in m_meta,
        //  retry with response urlencoded as a single parameter name with no value
        // no response body
        //TODO: implement lol
        break;
    case GeminiProtocol::StatusCode::Success:
        //3.2.2 - [2x] SUCCESS
        // response body
        //ref1 section 3.3: Response bodies
        // if META is empty, it MUST default to text/gemini;charset=utf-8;lang=en
        //ref1 section 5.2: Parameters conflicts - this dictates that a single
        // parameter, lang, may be specified, and its default should be context-
        //  dependent and decided by the client (ie., the user's own language)
        // however section 3.3 specifies a charset parameter with a default
        //  value of utf-8. I will simply implement both.
        // The spec for a 2x meta is thus interpreted as
        //  <mimetype>[;charset=<charset>][;lang=<lang>]
        // and the order of optional parameters is not fixed
        if (m_meta.length() == 0)
            m_meta = "text/gemini; charset=utf-8; lang=en";
        else {
            auto metas = m_meta.replace(' ',"").split(';');
            m_content_type = metas.at(0);
            metas.remove(0);
            foreach(auto m, metas) {
                auto kv = m.split('=');
                if(kv.length() != 2)
                    qDebug() << "E: parse_header: 2x: meta: params: param was not a key=val:" << m;
                else {
                    if(kv.at(0) == "charset")
                        m_charset = kv.at(1);
                    else if(kv.at(0) == "lang")
                        m_lang = kv.at(1);
                    else
                        qDebug() << "E: parse_header: 2x: meta: params: unrecognised param:" << m;
                }
            }
        }
        if(m_content_type.length() == 0) m_content_type="text/gemini";
        if(m_lang.length() < 2) m_lang="en";
        if(m_charset.length() == 0) m_charset="utf-8";
        break;
    case GeminiProtocol::StatusCode::RedirectTemporary:
    case GeminiProtocol::StatusCode::RedirectPermanent:
        //3.2.3 - [3x] REDIRECT
        // disconnect, m_meta contains a relative or absolute URI to be used instead.
        //  client MUST NOT honour a previous INPUT response when following a REDIRECT
        // no response body
        //TODO: implement lol
        if(m_meta.length() == 0)
            emit dooble_gemini_implementation::error(QWebEngineUrlRequestJob::Error::RequestFailed);
        break;
    case GeminiProtocol::StatusCode::FailureTemporary:
    case GeminiProtocol::StatusCode::FailureServerUnavailable:
    case GeminiProtocol::StatusCode::FailureCgiError:
    case GeminiProtocol::StatusCode::FailureProxyError:
    case GeminiProtocol::StatusCode::FailureSlowDown:
        //3.2.4 - [4x] TEMPORARY FAILURE
        // disconnect, m_meta contains any additional information, should be shown to user
        // request may be retried
        //  no response body
        //TODO: implement lol
        emit dooble_gemini_implementation::error(QWebEngineUrlRequestJob::Error::RequestFailed);
        break;
    case GeminiProtocol::StatusCode::FailurePermanent:
    case GeminiProtocol::StatusCode::NotFound:
    case GeminiProtocol::StatusCode::Gone:
    case GeminiProtocol::StatusCode::FailureProxyRequestRefused:
    case GeminiProtocol::StatusCode::FailureBadRequest:
        //3.2.5 - [5x] PERMANENT FAILURE
        // disconnect, m_meta contains any additional information, should be shown to user
        // request may not be retried
        //  no response body
        //TODO: implement lol
        emit dooble_gemini_implementation::error(QWebEngineUrlRequestJob::Error::RequestFailed);
        break;
    case GeminiProtocol::StatusCode::ClientCertificateRequired:
    case GeminiProtocol::StatusCode::ClientCertificateNotAuthorised:
    case GeminiProtocol::StatusCode::ClientCertificateNotValid:
        //3.2.6 - [6x] CLIENT CERTIFICATE REQUIRED
        //
        emit dooble_gemini_implementation::error(QWebEngineUrlRequestJob::Error::RequestFailed);
        break;
    case GeminiProtocol::StatusCode::Unknown:
    default:
        qDebug() << "E: unhandled m_status_code" << m_status_code;
    }

    return true;
}
QByteArray dooble_gemini_implementation::plain_to_html(const QByteArray &bytes)
{
  qDebug() << "Entered plain_to_html with the following number of bytes:" << bytes.length();
  auto b(bytes);
  QList<QByteArray> rls = {};
  QRegularExpression headRe("^([#]+) ?(.*)\r?$");
  QRegularExpression hrefRe("^=> ?([a-zA-Z0-9\\-\\./_:~?%@]*)([\t ](.*))?\r?$");
  QRegularExpression liRe("^\\*[\t ]?(.*)\r?$");
  foreach(auto l, b.split('\n')) {
      //``` 5.4.3 Preformatting toggle lines
      if (l.startsWith("```")) {
          if(m_inside_list) {
              m_inside_list = false;
              rls.append("</ul>");
          }
          //this needed to be a non-static function because this function can be called
          // repeatedly as more content comes in from the server, and we need to track state..
          // it seems to be in 4kb chunks.
          if(m_inside_pre) {
              rls.append("</pre>");
              m_inside_pre = false;
          } else {
              rls.append("<pre>");
              m_inside_pre = true;
          }
      } else if (m_inside_pre) {
          rls.append(l);
      } else if(l.startsWith("=>")) {
          if(m_inside_list) {
              m_inside_list = false;
              rls.append("</ul>");
          }
          //https://gemini.circumlunar.space/docs/specification.gmi section 5.4.2 Link lines
          auto ml = hrefRe.match(l);
          if(!ml.isValid()) {
              l.replace('\r', "<br/>");
              if(!l.endsWith("<br/>"))
                l.append("<br/>");
              rls.append(l);
          } else {
              if(ml.lastCapturedIndex()==3)
                    rls.append(QString("<a href=\"%1\">%2</a><br/>")
                               .arg(ml.captured(1),
                                    ml.captured(3))
                               .toUtf8());
              else
                  rls.append(QString("<a href=\"%1\">%1</a><br/>")
                             .arg(ml.captured(1))
                             .toUtf8());
          }
      } else if (l.startsWith('#')) {
          auto ml = headRe.match(l);
          if(!ml.isValid() || ml.lastCapturedIndex() != 2) {
              l.replace('\r', "<br/>");
              if(!l.endsWith("<br/>"))
                l.append("<br/>");
              rls.append(l);
          //technically this breaks the gemdoc spec, because it permits
          // header levels above h3, but all other implementations really felt gross
          // why am i so bad at c++
          } else {
              //how in the world do i rotate text in mspaint
              QString h;
              h.setNum(ml.captured(1).length());
              //literally if i do <h%1> then it seems like it breaks string formatting
              // and the output is -literally- <h%1>, and the docs don't say how to
              // denote the beginning and end of a string formatting thing, so idk
              // if there's like, <h{%1}> or what.
              rls.append(QString("<h`>%1</h`>").replace('`', h)
                          .arg(ml.captured(2)).toUtf8());
          }
      } else if (l.startsWith('*')) {
          //* 5.5.2 Unordered list items
          auto ml = liRe.match(l);
          if(!m_inside_list) {
              m_inside_list = true;
              rls.append("<ul>");
          }
          rls.append(QString("<li>%1</li>").arg(ml.captured(1)).toUtf8());
      } else {
          if(m_inside_list) {
              m_inside_list = false;
              rls.append("</ul>");
          }
          //TODO: > 5.5.3 Quote lines
          //at some point when i got unicode working, this stopped working.
          l.replace('\r', "<br/>");
          if (!l.endsWith("<br/>"))
            l.append("<br/>");
          /*l.replace("<", "&lt;");
          l.replace(">", "&gt;");
          l.replace("&", "&amp;");
          l.replace(" ", "&nbsp;");*/
          rls.append(l);
      }
  }

  return rls.join("\n");;
}

void dooble_gemini_implementation::slot_connected(void)
{
    qDebug() << "SIG: Connected";
}

void dooble_gemini_implementation::slot_encrypted(void)
{
  qDebug() << "SIG: Encrypted";
  QString output("");
  //ref1 section 2: Gemini requests
  //client MUST send an absolute URL followed by s_eol, and nothing else
  auto scheme(m_url.scheme());
  auto host(m_url.host());
  auto path(m_url.path());
  auto query(m_url.query());
  output.append(scheme);
  output.append("://");
  output.append(host);

  if(path.length() <= 1)
      output.append("/");
  else
      output.append(path);

  if(!query.isEmpty())
    {
      output.append("?");
      output.append(query);
    }
  output.append("\r\n");
  qDebug() << "Request, as sent to the server:" << output;
  m_output = output;
  m_web_engine_view->page()->runJavaScript
    ("if(document.getElementById(\"input_value\") != null)"
     "document.getElementById(\"input_value\").value",
     [this] (const QVariant &result)
     {
       m_search = result.toString();
     });
  m_write_timer.start(1500);
}

void dooble_gemini_implementation::slot_disconnected(void)
{
  qDebug() << "SIG: Disconnected";
  if(m_loaded)
    m_html.append("</body></html>");
  emit finished(m_html, m_content_type, m_status_code, m_charset, m_lang, m_meta);
}

void dooble_gemini_implementation::slot_ready_read(void)
{
  qDebug() << "SIG: ReadyRead";
  while(bytesAvailable() > 0)
    m_content.append(readAll());

  if(!m_loaded) {
      auto bytes(m_content.mid(0, m_content.indexOf(s_eol) + 2));
      m_header = bytes;
      m_content.remove(0, m_header.length());
      if (!parse_header(m_header)) {
          emit error(QWebEngineUrlRequestJob::Error::RequestFailed);
      }
      m_html.append(QString("<html charset=\"%1\" lang=\"%2\"><head><meta charset=\"%1\"/></head><body>")
                    .arg(m_charset, m_lang).toUtf8());
      m_html.append(QString("<p><b>Debug:</b><br/>Response Code: %1<br/>MIMEType: %2<br/>Character Encoding: %3<br/>Language: %4<br/>").arg(
                        QMetaEnum::fromType<GeminiProtocol::StatusCode::StatusCodeEnum>()
                            .valueToKey(m_status_code),
                        m_content_type, m_charset, m_lang).toUtf8());
      m_html.append("</p>");
      m_loaded = true;
  }
  if(m_content.length() > 0) {
    m_html.append(plain_to_html(m_content));
    m_content.clear();
  }

  if(false)
    {
      m_html.append
	("<html><head></head><body style=\"font-family: monospace\">");

      while(m_content.contains(s_eol))
	{
      auto bytes(m_content.mid(0, m_content.indexOf(s_eol) + 1));

	  m_content.remove(0, bytes.length());
	  bytes = bytes.trimmed();

	  auto c = bytes.length() > 0 ? bytes.at(0) : '0';

	  if(c == '+' ||
	     c == '0' ||
	     c == '1' ||
	     c == '3' ||
	     c == '4' ||
	     c == '5' ||
	     c == '6' ||
	     c == '9' ||
	     c == 'I' ||
	     c == 'g' ||
	     c == 'h' ||
	     c == 'i' ||
	     c == 's')
	    /*
	    ** Some things, we understand.
	    */

	    bytes.remove(0, 1);

	  auto list(bytes.split('\t'));

	  if(c == '+' ||
	     c == '0' ||
	     c == '1' ||
	     c == '4' ||
	     c == '5' ||
	     c == '6' ||
	     c == '9' ||
	     c == 'I' ||
	     c == 'g' ||
	     c == 'h' ||
	     c == 's')
	    {
	      auto port = list.value(3).toInt();

	      if(port <= 0)
		port = 70;

	      m_html.append
		(QString("<a href=\"gemini://%1:%2/%3%4\" "
			 "style=\"text-decoration: none;\">%5</a>%6<br>").
		 arg(list.value(2).trimmed().constData()).
		 arg(port).
		 arg(c).
		 arg(list.value(1).constData() + (list.value(1).
						  mid(0, 1) == "/")).
		 arg(plain_to_html(list.value(0)).constData()).
		 arg(c == '1' ? "..." : "").toUtf8());
	    }
	  else if(c == '3' || c == 'i')
 	    {
	      auto information(list.value(0));

	      if(c == 'i')
 		{
		  m_html.append(plain_to_html(information));
		  m_html.append("<br>");
 		}
 	      else
 		{
		  m_html.append("<span style=\"color: red;\">");
		  m_html.append(plain_to_html(information));
		  m_html.append("</span>");
		  m_html.append("<br>");
 		}
 	    }
	  else if(c == '7' && m_seven_count == 0)
	    {
	      /*
	      ** Create an input search field.
	      */

	      auto port = list.value(3).toInt();

	      if(port <= 0)
		port = 70;

	      m_html.append
		(QString("<form action=\"gemini://%1:%2/%3%4\" "
			 "method=\"post\">"
			 "<input id=\"input_value\" "
			 "placeholder=\"Search\" type=\"search\" "
			 "value=\"%5\"></input>"
			 "<button type=\"submit\">&#128269;</button>"
			 "</form><br>").
		 arg(list.value(2).trimmed().constData()).
		 arg(port).
		 arg(c).
		 arg(list.value(1).constData() + (list.value(1).
						  mid(0, 1) == "/")).
		 arg(m_search).toUtf8());
	      m_seven_count += 1;
	    }
	  else
 	    {
	      m_html.append(plain_to_html(bytes));
	      m_html.append("<br>");
 	    }
 	}

      m_html.append("</body></html>");
    }
}

void dooble_gemini_implementation::slot_write_timeout(void)
{
    qDebug() << "SIG: WriteTimeout";
  if(m_search.isEmpty())
    write(m_output.toUtf8().append(s_eol));
  else
    write
      (m_output.toUtf8().append("?").append(m_search.toUtf8()).append(s_eol));
}

void dooble_gemini_implementation::slot_statechange(QAbstractSocket::SocketState state)
{
    qDebug() << "SIG: StateChange:" << state;
}

void dooble_gemini_implementation::slot_peerverifyerror(QSslError err)
{
    qDebug() << "SIG: PeerVerifyError:" << err;
    ignoreSslErrors(QList<QSslError> { err });
}

void dooble_gemini_implementation::slot_sslerrors(const QList<QSslError> &errs)
{
    qDebug() << "SIG: SSLErrors:" << errs;
    ignoreSslErrors(errs);
}

void dooble_gemini_implementation::slot_sockerr(QAbstractSocket::SocketError)
{
    qDebug() << "SIG: SocketError:" << QAbstractSocket::error() << QAbstractSocket::errorString();
    ignoreSslErrors();
}

void dooble_gemini_implementation::slot_handshakeerror(const QSslError &e)
{
    qDebug() << "SIG: HandshakeError:" << e;
    continueInterruptedHandshake();
}

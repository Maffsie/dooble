//what copyright header should be here..?

//REFERENCES
// [1]: https://gemini.circumlunar.space/docs/specification.gmi (fetched 2022-02-08)

#include <cctype>

#include "dooble_gemini.h"
#include "dooble_web_engine_view.h"

//class dooble_gemini
dooble_gemini::dooble_gemini(QObject *parent): QWebEngineUrlSchemeHandler(parent)
{
}

void dooble_gemini::requestStarted(QWebEngineUrlRequestJob *request)
{
  if(m_request == request || !request)
    return;
  m_request = request;
  auto gemini_impl = new dooble_gemini_implementation
      (m_request->requestUrl(),
       qobject_cast<dooble_web_engine_view *> (parent()),
       m_request);

  connect(gemini_impl, &dooble_gemini_implementation::error,
          this, &dooble_gemini::slot_error);
  connect(gemini_impl, &dooble_gemini_implementation::finished,
          this, &dooble_gemini::slot_finished);
}

void dooble_gemini::slot_error(QWebEngineUrlRequestJob::Error error)
{
  if(m_request)
    m_request->fail(error);
}

void dooble_gemini::slot_finished(const QByteArray &bytes,
                                  QString content_type,
                                  StatusCode::StatusCodeEnum result,
                                  QString charset,
                                  QString lang,
                                  QString meta)
{
  if(m_request)
  {
    if(bytes.isEmpty())
      m_request->fail(QWebEngineUrlRequestJob::RequestFailed);
    else if(result == StatusCode::RedirectPermanent || result == StatusCode::RedirectTemporary)
      m_request->redirect(meta);
    else
    {
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
//end class dooble_gemini

// class dooble_gemini_implementation
QByteArray dooble_gemini_implementation::s_eol = "\r\n";

dooble_gemini_implementation::dooble_gemini_implementation
(const QUrl &url,
 dooble_web_engine_view *web_engine_view,
 QObject *parent): QSslSocket(parent)
{
  //qDebug() << "Connect begin";
  m_write_timer.setSingleShot(true);

  connect(this, &QAbstractSocket::stateChanged,
          this, &dooble_gemini_implementation::slot_statechange);
  connect(this, &QSslSocket::connected,
          this, &dooble_gemini_implementation::slot_connected);
  connect(this, &QSslSocket::encrypted,
          this, &dooble_gemini_implementation::slot_encrypted);
  connect(this, &QSslSocket::readyRead,
          this, &dooble_gemini_implementation::slot_ready_read);
  connect(this, &QSslSocket::disconnected,
          this, &dooble_gemini_implementation::slot_disconnected);
  connect(this, &QSslSocket::sslErrors,
          this, &dooble_gemini_implementation::slot_sslerrors);
  connect(this, &QSslSocket::peerVerifyError,
          this, &dooble_gemini_implementation::slot_peerverifyerror);
  connect(this, &QAbstractSocket::errorOccurred,
          this, &dooble_gemini_implementation::slot_sockerr);
  connect(this, &QSslSocket::handshakeInterruptedOnError,
          this, &dooble_gemini_implementation::slot_handshakeerror);
  connect(&m_write_timer, &QTimer::timeout,
          this, &dooble_gemini_implementation::slot_write_timeout);

  // i feel like this should really be a struct.
  // there's enough state information needed that
  // there really should be a struct.
  m_loaded = false;
  m_meta = "";
  m_status_code = StatusCode::Unknown;
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

  //ref1 s4.2 TLS: Server validation
  /* TODO
   * - Client must not accept TLS versions below 1.2 (done)
   * - Upon securely connecting to a server, client must:
   * -- Validate CA-signed certificate with either CA certs configured
   *    by the user, or with CA certs bundled with the operating system
   * -- Validate self-signed certificate by way of a "Trust On First Use"
   *    mechanism.
   * - In the case of a self-signed certificate, on first use the cert
   * 		fingerprint should be stored in a persistent location by the
   * 		client, along with the DNS name of the server.
   * 		The client should then flash a notice at the user, either by
   * 		way of a status message at the bottom, or by pop-up (a-la OpenSSH).
   * - If the client finds that the server's certificate has changed since
   * 		last connected, and the certificate is self-signed, raise a pop-up
   * 		notice to the user showing the previous and current fingerprints,
   * 		along with the validity periods, and the user may decide whether
   * 		to overwrite the previously trusted certificate, or refuse to
   * 		complete the connection.
   * - A way of viewing, adding and removing certificate<>host pairings
   *	 	should be made available in the client. A good way of
   *		accomplishing this would be to reuse the dialogue box used for
   *		configuring SSL exceptions in HTTPS pages, as well as the SQLite
   *		database which it uses for storage of these exceptions.
   */

  /* FIXME
   * On Mac OS 12 (other versions untested), it appears to be impossible
   * to have the QSslSocket emit an sslErrors signal and then handle that
   * signal as normal on other operating systems. The only signal emitted
   * is a SocketException, and the underlying SSL error is
   * CFNetwork: SSLHandshake error -9824 (error occurred during initial handshake)
   * Someone much smarter than I, please fix this, because it is beyond me.
   */
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

/* parse_header(QByteArray&)
 * Function to parse the first line of input from the server.
 * Returns: bool indicating if the header could be correctly
 * 					parsed.
 */
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

  m_status_code = StatusCode::StatusCodeEnum(hMatches.captured(1).toInt());
  if(hMatches.lastCapturedIndex() == 3)
    m_meta = hMatches.captured(3);

  switch (m_status_code)
  {
  case StatusCode::Input:
  case StatusCode::InputSensitive:
    //3.2.1 - [1x] INPUT
    //Not yet implemented.
    /*
     * INPUT responses indicate that the client should disconnect, and
     * prompt the user for input. 11 InputSensitive indicates that
     * the client may use more secure means of collecting input
     * from the user, or otherwise that the information supplied
     * by the user is
     */
    break;
  case StatusCode::Success:
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

    // (infomercial voice) there has to be a better way of doing this!
    if (m_meta.length() == 0)
      m_meta = "text/gemini; charset=utf-8; lang=en";
    else
    {
      auto metas = m_meta.replace(' ',"").split(';');
      m_content_type = metas.at(0);
      metas.remove(0);
      foreach(auto m, metas)
      {
        auto kv = m.split('=');
        if(kv.length() != 2)
          qDebug() << "Error while parsing META field for Success response: MIMEType parameter was not a key=value:" << m;
        else
        {
          if(kv.at(0) == "charset")
            m_charset = kv.at(1);
          else if(kv.at(0) == "lang")
            m_lang = kv.at(1);
          else
            qDebug() << "Error while parsing META field for Success response: MIMEType parameter was not recognised:" << m;
        }
      }
    }
    // Spec-mandated defaults
    if(m_content_type.length() == 0) m_content_type="text/gemini";
    if(m_lang.length() < 2) m_lang="en";
    if(m_charset.length() == 0) m_charset="utf-8";
    break;
  case StatusCode::RedirectTemporary:
  case StatusCode::RedirectPermanent:
    //3.2.3 - [3x] REDIRECT
    // disconnect, m_meta contains a relative or absolute URI to be used instead.
    //  client MUST NOT honour a previous INPUT response when following a REDIRECT
    // no response body
    if(m_meta.length() == 0)
      emit dooble_gemini_implementation::error(QWebEngineUrlRequestJob::Error::RequestFailed);
    break;
  case StatusCode::FailureTemporary:
  case StatusCode::FailureServerUnavailable:
  case StatusCode::FailureCgiError:
  case StatusCode::FailureProxyError:
  case StatusCode::FailureSlowDown:
    //3.2.4 - [4x] TEMPORARY FAILURE
    // disconnect, m_meta contains any additional information, should be shown to user
    // request may be retried
    //  no response body
    //Not yet implemented
    emit dooble_gemini_implementation::error(QWebEngineUrlRequestJob::Error::RequestFailed);
    break;
  case StatusCode::FailurePermanent:
  case StatusCode::NotFound:
  case StatusCode::Gone:
  case StatusCode::FailureProxyRequestRefused:
  case StatusCode::FailureBadRequest:
    //3.2.5 - [5x] PERMANENT FAILURE
    // disconnect, m_meta contains any additional information, should be shown to user
    // request may not be retried
    //  no response body
    //Not yet implemented
    emit dooble_gemini_implementation::error(QWebEngineUrlRequestJob::Error::RequestFailed);
    break;
  case StatusCode::ClientCertificateRequired:
  case StatusCode::ClientCertificateNotAuthorised:
  case StatusCode::ClientCertificateNotValid:
    //3.2.6 - [6x] CLIENT CERTIFICATE REQUIRED
    //Not yet implemented
    emit dooble_gemini_implementation::error(QWebEngineUrlRequestJob::Error::RequestFailed);
    break;
  case StatusCode::Unknown:
  default:
    qDebug() << "Error while parsing server response: Response code was not recognised:" << hMatches.captured(1);
    emit dooble_gemini_implementation::error(QWebEngineUrlRequestJob::Error::RequestFailed);
  }

  return true;
}

/* QByteArray plain_to_html(const QByteArray&)
 * Function to parse the text/gemini document type, and
 * render it as HTML.
 * Returns: QByteArray of the parsed and rendered document.
 */
QByteArray dooble_gemini_implementation::plain_to_html(const QByteArray &bytes)
{
  qDebug() << "Entered plain_to_html with the following number of bytes:" << bytes.length();
  auto b(bytes);
  QList<QByteArray> rls = {};
  //There absolutely must be a better way of doing this.
  // However, all I have is a hammer (regular expressions)
  // and the concept of parsing a document sure does look like a nail.
  //By this, I mean that I literally don't know how else to accomplish this.
  //I don't want to look at other implementations, lest I be accused of
  // plagiarism, and also I just kind of like reading specs instead.
  QRegularExpression headRe("^([#]+) ?(.*)\r?$");
  QRegularExpression hrefRe("^=>[\t ]*([a-zA-Z0-9\\-\\./_:~?%@&=]*)([\t ]*(.*))?\r?$");
  QRegularExpression liRe("^\\*[\t ]?(.*)\r?$");
  foreach(auto l, b.split('\n'))
  {
    //``` 5.4.3 Preformatting toggle lines
    if (l.startsWith("```"))
    {
      if(m_inside_list)
      {
        m_inside_list = false;
        rls.append("</ul>");
      }
      //this needed to be a non-static function because this function can be called
      // repeatedly as more content comes in from the server, and we need to track state..
      // it seems to be in 4kb chunks.
      if(m_inside_pre)
      {
        rls.append("</pre>");
        m_inside_pre = false;
      }
      else
      {
        rls.append("<pre>");
        m_inside_pre = true;
      }
    }
    else if (m_inside_pre)
    {
      rls.append(l);
    }
    else if(l.startsWith("=>"))
    {
      if(m_inside_list)
      {
        m_inside_list = false;
        rls.append("</ul>");
      }
      //https://gemini.circumlunar.space/docs/specification.gmi section 5.4.2 Link lines
      auto ml = hrefRe.match(l);
      if(!ml.isValid())
      {
        l.replace('\r', "<br/>");
        if(!l.endsWith("<br/>"))
          l.append("<br/>");
        rls.append(l);
      }
      else
      {
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
    }
    else if (l.startsWith('#'))
    {
      auto ml = headRe.match(l);
      if(!ml.isValid() || ml.lastCapturedIndex() != 2)
      {
        l.replace('\r', "<br/>");
        if(!l.endsWith("<br/>"))
          l.append("<br/>");
        rls.append(l);
        //technically this breaks the gemdoc spec, because it permits
        // header levels above h3, but all other implementations really felt gross
        // why am i so bad at c++
      }
      else
      {
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
    }
    else if (l.startsWith('*'))
    {
      //* 5.5.2 Unordered list items
      auto ml = liRe.match(l);
      if(!m_inside_list)
      {
        m_inside_list = true;
        rls.append("<ul>");
      }
      rls.append(QString("<li>%1</li>").arg(ml.captured(1)).toUtf8());
    }
    else
    {
      if(m_inside_list)
      {
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
  //qDebug() << "SIG: Connected";
}

void dooble_gemini_implementation::slot_encrypted(void)
{
  //qDebug() << "SIG: Encrypted";
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
  //qDebug() << "Request, as sent to the server:" << output;
  m_output = output;
  m_web_engine_view->page()->runJavaScript
      ("if(document.getElementById(\"input_value\") != null)"
       "document.getElementById(\"input_value\").value",
       [this] (const QVariant &result)
  {
    m_search = result.toString();
  });
  // Maybe the timer should be adjustable..?
  m_write_timer.start(1500);
}

void dooble_gemini_implementation::slot_disconnected(void)
{
  //qDebug() << "SIG: Disconnected";
  if(m_loaded && m_content_type == "text/gemini")
    m_html.append("</body></html>");
  emit finished(m_html, m_content_type, m_status_code, m_charset, m_lang, m_meta);
}

void dooble_gemini_implementation::slot_ready_read(void)
{
  //qDebug() << "SIG: ReadyRead";
  //When testing implementation, I've seen that sometimes
  // a server will respond with 4096 bytes, and then the
  // ready_read state will begin again with the next 4096.
  //I'm not sure if this is a client-side buffer thing or what.
  while(bytesAvailable() > 0)
    m_content.append(readAll());

  if(!m_loaded)
  {
    auto bytes(m_content.mid(0, m_content.indexOf(s_eol) + 2));
    m_header = bytes;
    m_content.remove(0, m_header.length());
    if (!parse_header(m_header))
      emit error(QWebEngineUrlRequestJob::Error::RequestFailed);
    if(m_content_type.startsWith("text"))
    {
      auto hdr = QString("Response: %1\nMeta: %2\nMIME: %3\nCharset: %4\nLang: %5\n");
      if(m_content_type == "text/gemini")
        hdr = QString("<html charset=\"%4\" lang=\"%5\"><head><meta charset=\"%4\"/></head><body><p><b>Response: </b>%1<br/><b>Meta: </b>%2<br/><b>MIME: </b>%3<br/><b>Charset: </b>%4<br/><b>Lang: </b>%5</p>");
      m_html.append(hdr.arg(QMetaEnum::fromType
                            <StatusCode::StatusCodeEnum>
                            ().valueToKey(m_status_code),
                            m_meta, m_content_type, m_charset, m_lang).toUtf8());
    }
    m_loaded = true;
  }
  if(m_content.length() > 0)
  {
    if(m_content_type == "text/gemini")
      m_html.append(plain_to_html(m_content));
    else m_html.append(m_content);
    m_content.clear();
  }
}

void dooble_gemini_implementation::slot_write_timeout(void)
{
  //qDebug() << "SIG: WriteTimeout";
  if(m_search.isEmpty())
    write(m_output.toUtf8().append(s_eol));
  else
    write
        (m_output.toUtf8().append("?").append(m_search.toUtf8()).append(s_eol));
}

void dooble_gemini_implementation::slot_statechange(QAbstractSocket::SocketState)
{
  //qDebug() << "SIG: StateChange:" << state;
}

void dooble_gemini_implementation::slot_peerverifyerror(QSslError err)
{
  //qDebug() << "SIG: PeerVerifyError:" << err;
  ignoreSslErrors(QList<QSslError> { err });
}

void dooble_gemini_implementation::slot_sslerrors(const QList<QSslError> &errs)
{
  //qDebug() << "SIG: SSLErrors:" << errs;
  ignoreSslErrors(errs);
}

void dooble_gemini_implementation::slot_sockerr(QAbstractSocket::SocketError)
{
  //qDebug() << "SIG: SocketError:" << QAbstractSocket::error() << QAbstractSocket::errorString();
  //ignoreSslErrors();
}

void dooble_gemini_implementation::slot_handshakeerror(const QSslError &)
{
  //qDebug() << "SIG: HandshakeError:" << e;
  continueInterruptedHandshake();
}

//end class dooble_gemini_implementation

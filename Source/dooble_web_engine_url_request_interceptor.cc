/*
** Copyright (c) 2008 - present, Alexis Megas.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote products
**    derived from Dooble without specific prior written permission.
**
** DOOBLE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
** OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
** NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
** DOOBLE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "dooble.h"
#include "dooble_accepted_or_blocked_domains.h"
#include "dooble_web_engine_url_request_interceptor.h"

dooble_web_engine_url_request_interceptor::
dooble_web_engine_url_request_interceptor(QObject *parent):
  QWebEngineUrlRequestInterceptor(parent)
{
}

void dooble_web_engine_url_request_interceptor::
interceptRequest(QWebEngineUrlRequestInfo &info)
{
  if(dooble_settings::setting("do_not_track").toBool())
    info.setHttpHeader("DNT", "1");

  if(dooble_settings::setting("referrer").toBool() == false)
    info.setHttpHeader("REFERER", "");

  auto mode
    (dooble_settings::setting("accepted_or_blocked_domains_mode").toString());

  if(dooble::s_accepted_or_blocked_domains->exception(info.firstPartyUrl()))
    {
      if(mode == "accept")
	info.block(true);
      else
	info.block(false);

      return;
    }

  QString host("");
  auto state = true;
  int index = -1;

  if(mode == "accept")
    {
      host = info.firstPartyUrl().host();
      info.block(true);
      state = false;
    }
  else
    {
      host = info.requestUrl().host();
      state = true;
    }

  while(!host.isEmpty())
    if(dooble::s_accepted_or_blocked_domains->contains(host))
      {
	info.block(state);
	return;
      }
    else if((index = host.indexOf('.')) > 0)
      host.remove(0, index + 1);
    else
      break;
}
